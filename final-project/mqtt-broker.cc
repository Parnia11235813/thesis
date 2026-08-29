#include "mqtt-broker.h"

#include "ns3/core-module.h"

#include "mqtt-wire.h"
#include "research-payload.h"
#include "scenario-state.h"

using namespace ns3;

namespace
{

bool
BrokerAcceptRequest(Ptr<Socket>, const Address&)
{
    return true;
}

void
ForwardAcceptedPublish(const Mqtt::PublishView& incoming,
                       bool isAttack)
{
    if (!g_subscriberSubscribed ||
        g_brokerSubscriberSocket == nullptr)
    {
        ++g_state.brokerForwardSendFailures;
        return;
    }

    const uint16_t forwardPacketId =
        NextPacketId(g_nextBrokerPacketId);

    const std::vector<uint8_t> forwarded =
        Mqtt::BuildPublishQos1(
            incoming.topic,
            forwardPacketId,
            incoming.payload);

    ++g_state.brokerForwardSendAttempts;

    const int sent =
        g_brokerSubscriberSocket->Send(
            Mqtt::ToNs3Packet(forwarded));

    if (sent > 0)
    {
        ++g_state.brokerForwardSendSuccess;
        g_brokerPendingPubacks[forwardPacketId] = !isAttack;

        if (isAttack)
        {
            ++g_state.brokerAttackForwardSendSuccess;
        }
        else
        {
            ++g_state.brokerLegitimateForwardSendSuccess;
        }
    }
    else
    {
        ++g_state.brokerForwardSendFailures;
    }
}

void
ProcessBrokerPacket(Ptr<Socket> socket,
                    const Mqtt::PacketView& packet)
{
    if (packet.type ==
        static_cast<uint8_t>(Mqtt::Type::CONNECT))
    {
        if (g_brokerClientConnected[socket])
        {
            ++g_state.unexpectedPackets;
            return;
        }

        if (packet.body.size() < 10)
        {
            ++g_state.malformedPackets;
            return;
        }

        socket->Send(
            Mqtt::ToNs3Packet(Mqtt::BuildConnAck()));

        g_brokerClientConnected[socket] = true;

        ++g_state.connackPacketsSent;
        return;
    }

    if (!g_brokerClientConnected[socket])
    {
        ++g_state.unexpectedPackets;
        return;
    }

    if (packet.type ==
        static_cast<uint8_t>(Mqtt::Type::SUBSCRIBE))
    {
        uint16_t packetId = 0;
        std::string topicFilter;
        uint8_t requestedQos = 0;

        if (!Mqtt::ParseSubscribe(
                packet,
                packetId,
                topicFilter,
                requestedQos))
        {
            ++g_state.malformedPackets;
            return;
        }

        if (topicFilter != MQTT_TOPIC)
        {
            ++g_state.unexpectedPackets;
            return;
        }

        g_brokerSubscriberSocket = socket;

        socket->Send(Mqtt::ToNs3Packet(
            Mqtt::BuildSubAck(packetId, 1)));

        ++g_state.subackPacketsSent;
        return;
    }

    if (packet.type ==
        static_cast<uint8_t>(Mqtt::Type::PUBACK))
    {
        uint16_t packetId = 0;

        if (!Mqtt::ParsePacketIdentifier(packet, packetId))
        {
            ++g_state.malformedPackets;
            return;
        }

        auto it = g_brokerPendingPubacks.find(packetId);

        if (it == g_brokerPendingPubacks.end())
        {
            ++g_state.unexpectedPackets;
            return;
        }

        ++g_state.brokerSubscriberPubacksReceived;
        g_brokerPendingPubacks.erase(it);
        return;
    }

    if (packet.type ==
        static_cast<uint8_t>(Mqtt::Type::PUBLISH))
    {
        const Mqtt::PublishView publish =
            Mqtt::ParsePublish(packet);

        if (!publish.valid ||
            publish.topic != MQTT_TOPIC)
        {
            ++g_state.malformedPackets;
            return;
        }

        uint32_t publisherId = 0;
        uint64_t sequence = 0;

        if (!ParseResearchPayload(
                publish.payload,
                publisherId,
                sequence))
        {
            ++g_state.malformedPackets;
            return;
        }

        // Security-critical decision: the client's role comes from the
        // connection-time classification stored in g_brokerClientRole
        // (keyed by TCP/IP identity), never from application payload
        // content, which is forgeable in the real world.
        const ClientRole role =
            g_brokerClientRole[socket];

        const bool isAttack =
            role == ClientRole::ATTACKER;

        if (isAttack)
        {
            ++g_state.brokerAttackMessagesReceived;
        }
        else if (role == ClientRole::PUBLISHER)
        {
            ++g_state.brokerLegitimateMessagesReceived;
        }
        else
        {
            ++g_state.unexpectedPackets;
            return;
        }

        // Cross-check application identity against the selected attack profile.
        if (!isAttack &&
            publisherId != LEGITIMATE_PUBLISHER_ID)
        {
            ++g_state.unexpectedPackets;
            return;
        }

        if (isAttack)
        {
            if (g_attackKind == AttackKind::INJECTION &&
                publisherId != INJECTION_PUBLISHER_ID)
            {
                ++g_state.unexpectedPackets;
                return;
            }

            if ((g_attackKind == AttackKind::REPLAY ||
                 g_attackKind == AttackKind::DOS) &&
                publisherId != LEGITIMATE_PUBLISHER_ID)
            {
                ++g_state.unexpectedPackets;
                return;
            }
        }

        // MQTT QoS 1 acknowledgement is protocol-level.
        socket->Send(Mqtt::ToNs3Packet(
            Mqtt::BuildPubAck(publish.packetId)));

        ++g_state.brokerPubacksSent;

        bool accepted = true;

        // ---------------------------------------------------------------------
        // Security pipeline:
        //   Auth/ACL -> Freshness -> Rate Limiting -> Forwarding
        // ---------------------------------------------------------------------

        // 1) Authentication + ACL
        if (isAttack &&
            g_authAclEnabled &&
            !g_attackerAuthorized)
        {
            accepted = false;
            ++g_state.attackMessagesRejectedAuthAcl;
        }

        // 2) Freshness / Anti-Replay
        if (accepted &&
            isAttack &&
            g_attackKind == AttackKind::REPLAY &&
            g_freshnessEnabled)
        {
            auto highestIt =
                g_highestAcceptedSequence.find(publisherId);

            if (highestIt != g_highestAcceptedSequence.end() &&
                sequence <= highestIt->second)
            {
                accepted = false;
                ++g_state.attackMessagesRejectedFreshness;
            }
        }

        // Legitimate traffic advances freshness state.
        if (!isAttack &&
            publisherId == LEGITIMATE_PUBLISHER_ID)
        {
            auto highestIt =
                g_highestAcceptedSequence.find(publisherId);

            if (highestIt == g_highestAcceptedSequence.end() ||
                sequence > highestIt->second)
            {
                g_highestAcceptedSequence[publisherId] = sequence;
            }
        }

        // 3) Rate limiting
        if (accepted &&
            isAttack &&
            g_attackKind == AttackKind::DOS &&
            !RateLimitAccept(true))
        {
            accepted = false;
            ++g_state.attackMessagesRateLimited;
        }

        if (isAttack && accepted)
        {
            ++g_state.attackMessagesAccepted;
        }

        if (accepted)
        {
            ForwardAcceptedPublish(
                publish,
                isAttack);
        }

        return;
    }

    ++g_state.unexpectedPackets;
}

void
HandleBrokerRead(Ptr<Socket> socket)
{
    auto& buffer = g_brokerBuffers[socket];

    while (Ptr<Packet> p = socket->Recv())
    {
        if (p->GetSize() == 0)
        {
            break;
        }

        const size_t oldSize = buffer.size();
        buffer.resize(oldSize + p->GetSize());

        p->CopyData(
            buffer.data() + oldSize,
            p->GetSize());

        Mqtt::PacketView packet;

        while (Mqtt::TryExtractPacket(buffer, packet))
        {
            ProcessBrokerPacket(socket, packet);
        }
    }
}

void
BrokerAccept(Ptr<Socket> socket, const Address& from)
{
    g_brokerBuffers[socket] = {};
    g_brokerClientConnected[socket] = false;
    g_brokerClientRole[socket] = ClientRole::UNKNOWN;

    if (InetSocketAddress::IsMatchingType(from))
    {
        const InetSocketAddress remote =
            InetSocketAddress::ConvertFrom(from);

        if (remote.GetIpv4() == g_publisherIp)
        {
            g_brokerClientRole[socket] = ClientRole::PUBLISHER;
        }
        else if (remote.GetIpv4() == g_subscriberIp)
        {
            g_brokerClientRole[socket] = ClientRole::SUBSCRIBER;
        }
        else if (remote.GetIpv4() == g_attackerIp)
        {
            g_brokerClientRole[socket] = ClientRole::ATTACKER;
        }
    }

    socket->SetRecvCallback(
        MakeCallback(&HandleBrokerRead));
}

} // namespace

Ptr<Socket>
CreateListeningTcpSocket(Ptr<Node> node,
                         Ipv4Address address,
                         uint16_t port)
{
    Ptr<Socket> socket =
        Socket::CreateSocket(
            node,
            TcpSocketFactory::GetTypeId());

    if (socket->Bind(
            InetSocketAddress(address, port)) != 0)
    {
        NS_FATAL_ERROR("Broker TCP Bind failed");
    }

    if (socket->Listen() != 0)
    {
        NS_FATAL_ERROR("Broker TCP Listen failed");
    }

    socket->SetAcceptCallback(
        MakeCallback(&BrokerAcceptRequest),
        MakeCallback(&BrokerAccept));

    return socket;
}
