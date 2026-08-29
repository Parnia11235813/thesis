#include "mqtt-publisher.h"

#include "ns3/core-module.h"

#include "mqtt-wire.h"
#include "research-payload.h"
#include "scenario-state.h"

using namespace ns3;

void
PublisherConnectSucceeded(Ptr<Socket> socket)
{
    socket->Send(Mqtt::ToNs3Packet(
        Mqtt::BuildConnect("legitimate-publisher")));

    ++g_state.connectPacketsSent;
}

void
PublisherConnectFailed(Ptr<Socket>)
{
    NS_FATAL_ERROR("Publisher TCP connection to broker failed");
}

void
HandlePublisherRead(Ptr<Socket> socket)
{
    while (Ptr<Packet> p = socket->Recv())
    {
        if (p->GetSize() == 0)
        {
            break;
        }

        const size_t oldSize = g_publisherBuffer.size();
        g_publisherBuffer.resize(oldSize + p->GetSize());

        p->CopyData(
            g_publisherBuffer.data() + oldSize,
            p->GetSize());

        Mqtt::PacketView packet;

        while (Mqtt::TryExtractPacket(g_publisherBuffer, packet))
        {
            if (packet.type ==
                static_cast<uint8_t>(Mqtt::Type::CONNACK))
            {
                if (packet.body.size() == 2 &&
                    packet.body[1] == 0x00)
                {
                    g_publisherMqttConnected = true;
                    ++g_state.connackPacketsReceived;
                }
                else
                {
                    ++g_state.malformedPackets;
                }
            }
            else if (packet.type ==
                     static_cast<uint8_t>(Mqtt::Type::PUBACK))
            {
                uint16_t packetId = 0;

                if (!Mqtt::ParsePacketIdentifier(packet, packetId))
                {
                    ++g_state.malformedPackets;
                    continue;
                }

                auto it = g_publisherPendingPubacks.find(packetId);

                if (it == g_publisherPendingPubacks.end())
                {
                    ++g_state.unexpectedPackets;
                    continue;
                }

                g_state.publisherPubackDelaySumSeconds +=
                    Simulator::Now().GetSeconds() - it->second;

                ++g_state.publisherPubackDelaySamples;
                ++g_state.publisherPubacksReceived;

                g_publisherPendingPubacks.erase(it);
            }
            else
            {
                ++g_state.unexpectedPackets;
            }
        }
    }
}

void
SendLegitimatePublish()
{
    if (Simulator::Now() >= g_trafficStop)
    {
        return;
    }

    if (!g_publisherMqttConnected)
    {
        Simulator::Schedule(
            MilliSeconds(10),
            &SendLegitimatePublish);
        return;
    }

    const uint64_t sequence = g_nextLegitSequence++;
    const uint16_t packetId =
        NextPacketId(g_nextPublisherPacketId);

    const std::vector<uint8_t> payload =
        CreateResearchPayload(
            LEGITIMATE_PUBLISHER_ID,
            sequence,
            g_payloadBytes);

    if (g_attackKind == AttackKind::REPLAY &&
        !g_replayPayloadCaptured &&
        sequence == g_replaySequence)
    {
        g_capturedReplayPayload = payload;
        g_replayPayloadCaptured = true;
    }

    const std::vector<uint8_t> mqttPacket =
        Mqtt::BuildPublishQos1(
            MQTT_TOPIC,
            packetId,
            payload);

    const int sent =
        g_publisherSocket->Send(
            Mqtt::ToNs3Packet(mqttPacket));

    if (sent > 0)
    {
        ++g_state.publisherMessagesSent;

        const double now = Simulator::Now().GetSeconds();

        g_publisherPendingPubacks[packetId] = now;
        g_legitimateSendTimes[sequence] = now;
    }

    Simulator::Schedule(
        g_publishInterval,
        &SendLegitimatePublish);
}
