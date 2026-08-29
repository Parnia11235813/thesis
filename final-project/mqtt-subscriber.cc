#include "mqtt-subscriber.h"

#include "ns3/core-module.h"

#include "mqtt-wire.h"
#include "research-payload.h"
#include "scenario-state.h"

using namespace ns3;

void
SubscriberConnectSucceeded(Ptr<Socket> socket)
{
    socket->Send(Mqtt::ToNs3Packet(
        Mqtt::BuildConnect("telemetry-subscriber")));

    ++g_state.connectPacketsSent;
}

void
SubscriberConnectFailed(Ptr<Socket>)
{
    NS_FATAL_ERROR("Subscriber TCP connection to broker failed");
}

void
HandleSubscriberRead(Ptr<Socket> socket)
{
    while (Ptr<Packet> p = socket->Recv())
    {
        if (p->GetSize() == 0)
        {
            break;
        }

        const size_t oldSize = g_subscriberBuffer.size();
        g_subscriberBuffer.resize(oldSize + p->GetSize());

        p->CopyData(
            g_subscriberBuffer.data() + oldSize,
            p->GetSize());

        Mqtt::PacketView packet;

        while (Mqtt::TryExtractPacket(g_subscriberBuffer, packet))
        {
            if (packet.type ==
                static_cast<uint8_t>(Mqtt::Type::CONNACK))
            {
                if (packet.body.size() != 2 ||
                    packet.body[1] != 0x00)
                {
                    ++g_state.malformedPackets;
                    continue;
                }

                g_subscriberMqttConnected = true;
                ++g_state.connackPacketsReceived;

                socket->Send(Mqtt::ToNs3Packet(
                    Mqtt::BuildSubscribe(
                        MQTT_TOPIC,
                        1,
                        1)));

                ++g_state.subscribePacketsSent;
            }
            else if (packet.type ==
                     static_cast<uint8_t>(Mqtt::Type::SUBACK))
            {
                uint16_t packetId = 0;

                if (packet.body.size() != 3 ||
                    !Mqtt::ParsePacketIdentifier(packet, packetId) ||
                    packetId != 1 ||
                    packet.body[2] != 0x01)
                {
                    ++g_state.malformedPackets;
                    continue;
                }

                g_subscriberSubscribed = true;
                ++g_state.subackPacketsReceived;
            }
            else if (packet.type ==
                     static_cast<uint8_t>(Mqtt::Type::PUBLISH))
            {
                const Mqtt::PublishView publish =
                    Mqtt::ParsePublish(packet);

                if (!publish.valid ||
                    publish.topic != MQTT_TOPIC)
                {
                    ++g_state.malformedPackets;
                    continue;
                }

                uint32_t publisherId = 0;
                uint64_t sequence = 0;

                if (!ParseResearchPayload(
                        publish.payload,
                        publisherId,
                        sequence))
                {
                    ++g_state.malformedPackets;
                    continue;
                }

                // Origin (legitimate vs. attack) is read from the broker's
                // ground-truth map keyed by this forwarded Packet
                // Identifier, NOT from the payload's publisherId field. This
                // is a simulator-internal measurement channel (the whole
                // scenario runs in one process) used only for accurate
                // metrics — it is not something transmitted on the wire in
                // a real deployment, and it means metrics stay correctly
                // classified even if an attack could someday forge a
                // legitimate-looking publisherId.
                auto originIt =
                    g_brokerPendingPubacks.find(publish.packetId);

                if (originIt == g_brokerPendingPubacks.end())
                {
                    ++g_state.unexpectedPackets;
                    continue;
                }

                const bool originalLegitimate = originIt->second;

                ++g_state.subscriberMessagesReceived;

                if (originalLegitimate)
                {
                    ++g_state.subscriberLegitimateMessagesReceived;

                    auto it = g_legitimateSendTimes.find(sequence);

                    if (it != g_legitimateSendTimes.end())
                    {
                        g_state.legitimateEndToEndDelaySumSeconds +=
                            Simulator::Now().GetSeconds() - it->second;

                        ++g_state.legitimateEndToEndDelaySamples;

                        // The timestamp is no longer needed after the
                        // end-to-end delay sample has been recorded.
                        g_legitimateSendTimes.erase(it);
                    }
                }
                else
                {
                    ++g_state.subscriberAttackMessagesReceived;
                }

                socket->Send(Mqtt::ToNs3Packet(
                    Mqtt::BuildPubAck(publish.packetId)));

                ++g_state.subscriberPubacksSent;
            }
            else
            {
                ++g_state.unexpectedPackets;
            }
        }
    }
}
