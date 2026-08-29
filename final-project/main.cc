#include <cstdint>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"

#include "mqtt-attacker.h"
#include "mqtt-broker.h"
#include "mqtt-publisher.h"
#include "mqtt-subscriber.h"
#include "scenario-state.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("MqttQos1SecurityGameWire");

// =============================================================================
// MQTT 3.1.1 QoS 1 + DoS research scenario -- orchestration
// =============================================================================
//
// Topology:
//   Publisher  -----------+
//                           |
//   Attacker  --------------+--> Broker <------- Subscriber
//                     MQTT/TCP
//
// MQTT exchanges:
//   Publisher -> CONNECT
//   Broker    -> CONNACK
//
//   Subscriber -> CONNECT
//   Broker     -> CONNACK
//   Subscriber -> SUBSCRIBE(topic, QoS 1)
//   Broker     -> SUBACK
//
//   Publisher/Attacker -> PUBLISH(topic, QoS 1, Packet Identifier)
//   Broker              -> PUBACK(same Packet Identifier)
//
//   Broker     -> PUBLISH(topic, QoS 1, new server Packet Identifier)
//   Subscriber -> PUBACK(same Packet Identifier)
//
// Research security extension:
//   The broker classifies the attacker connection using its source IP.
//   When rate limiting is enabled, only attacker-originated PUBLISH messages
//   are limited. Legitimate traffic is never rate-limited in this isolated
//   scenario.
//
// IMPORTANT SCOPE:
//   This is a focused MQTT 3.1.1 wire-format implementation for the packet
//   types required by this experiment. It is NOT a complete production MQTT
//   broker. Session persistence, retained messages, wildcards,
//   authentication, reconnect processing, and retransmission after
//   connection loss are outside this scenario.
//
// This file is orchestration only: it parses CLI arguments, validates the
// configuration ("frozen timing" methodology), builds the network topology,
// runs the simulation, and prints metrics and validation flags as a
// structured JSON blob. All protocol/attack/defense logic lives in the
// mqtt-wire, research-payload, scenario-state, mqtt-publisher,
// mqtt-attacker, mqtt-subscriber, and mqtt-broker modules.
// =============================================================================

int
main(int argc, char* argv[])
{
    uint32_t rngSeed = 1;
    uint64_t run = 1;

    std::string attack = "none";

    double linkRateMbps = 10.0;
    uint32_t linkDelayUs = 100;

    uint32_t payloadBytes = 256;
    double publishRateHz = 20.0;

    // Frozen timing methodology:
    //   initialization:      [0, 1) s
    //   legitimate traffic: [1, 11) s
    //   attack window:      [4, 8) s
    //   post-traffic drain: [11, 20] s
    //
    // Defaults remain identical across clean, attack, and defended experiments.
    double simTime = 20.0;
    double trafficStart = 1.0;
    double trafficStop = 11.0;

    bool freshness = false;
    bool authAcl = false;
    bool attackerAuthorized = false;
    bool rateLimiting = false;

    double attackStart = 4.0;
    double attackStop = 8.0;
    double attackRateHz = 20.0;
    uint32_t attackCount = 20;
    uint64_t replaySequence = 1;

    double rateLimitHz = 50.0;

    CommandLine cmd(__FILE__);

    cmd.AddValue("rngSeed", "Master RNG seed", rngSeed);
    cmd.AddValue("run", "RNG run number", run);

    cmd.AddValue(
        "attack",
        "Attack type: none|replay|injection|dos",
        attack);

    cmd.AddValue(
        "freshness",
        "Enable freshness / anti-replay defense",
        freshness);

    cmd.AddValue(
        "authAcl",
        "Enable Authentication + ACL defense",
        authAcl);

    cmd.AddValue(
        "attackerAuthorized",
        "Whether the attacker is authorized by the security policy",
        attackerAuthorized);

    cmd.AddValue(
        "rateLimiting",
        "Enable broker-side DoS rate limiting",
        rateLimiting);

    cmd.AddValue(
        "attackRateHz",
        "Attack PUBLISH rate in messages per second",
        attackRateHz);

    cmd.AddValue(
        "attackCount",
        "Replay/Injection attempt count; ignored by DoS",
        attackCount);

    cmd.AddValue(
        "replaySequence",
        "Legitimate application sequence captured for Replay",
        replaySequence);

    cmd.AddValue(
        "rateLimitHz",
        "Maximum accepted DoS messages per one-second window",
        rateLimitHz);

    cmd.AddValue("attackStart", "Attack start time", attackStart);
    cmd.AddValue("attackStop", "Attack stop time", attackStop);

    cmd.AddValue("linkRateMbps", "CSMA link rate in Mbps", linkRateMbps);
    cmd.AddValue("linkDelayUs", "CSMA delay in microseconds", linkDelayUs);
    cmd.AddValue("payloadBytes", "Application data bytes", payloadBytes);
    cmd.AddValue("publishRateHz", "Legitimate PUBLISH rate", publishRateHz);
    cmd.AddValue("simTime", "Simulation duration", simTime);
    cmd.AddValue("trafficStart", "Legitimate traffic start", trafficStart);
    cmd.AddValue("trafficStop", "Legitimate traffic stop", trafficStop);

    cmd.Parse(argc, argv);

    g_attackKind = ParseAttackKind(attack);

    if (payloadBytes == 0 ||
        publishRateHz <= 0.0 ||
        linkRateMbps <= 0.0)
    {
        NS_FATAL_ERROR(
            "payloadBytes, publishRateHz, and linkRateMbps must be positive");
    }

    if (attackRateHz <= 0.0 &&
        g_attackKind != AttackKind::NONE)
    {
        NS_FATAL_ERROR("attackRateHz must be positive when attack != none");
    }

    if ((g_attackKind == AttackKind::REPLAY ||
         g_attackKind == AttackKind::INJECTION) &&
        attackCount == 0)
    {
        NS_FATAL_ERROR("attackCount must be greater than zero");
    }

    if (replaySequence == 0)
    {
        NS_FATAL_ERROR("replaySequence must be non-zero");
    }

    if (trafficStart >= trafficStop ||
        trafficStop >= simTime)
    {
        NS_FATAL_ERROR(
            "Invalid legitimate traffic timing: require "
            "trafficStart < trafficStop < simTime");
    }

    const double drainPeriod =
        simTime - trafficStop;

    if (drainPeriod < 9.0)
    {
        NS_FATAL_ERROR(
            "Frozen timing methodology requires a post-traffic drain "
            "period of at least 9 seconds");
    }

    if (g_attackKind != AttackKind::NONE)
    {
        if (attackStart <= trafficStart ||
            attackStart >= attackStop ||
            attackStop > simTime)
        {
            NS_FATAL_ERROR(
                "Invalid attack timing: require trafficStart < attackStart "
                "< attackStop <= simTime");
        }

        if (simTime <= attackStop)
        {
            NS_FATAL_ERROR(
                "simTime must exceed attackStop to provide a drain interval");
        }
    }

    if (g_attackKind == AttackKind::REPLAY)
    {
        const double captureTime =
            trafficStart +
            static_cast<double>(replaySequence - 1) / publishRateHz;

        if (attackStart <= captureTime)
        {
            NS_FATAL_ERROR(
                "attackStart must occur after replaySequence is published");
        }
    }

    if (g_attackKind == AttackKind::REPLAY ||
        g_attackKind == AttackKind::INJECTION)
    {
        const double duration =
            attackCount > 1
                ? static_cast<double>(attackCount - 1) / attackRateHz
                : 0.0;

        const double lastAttackSendTime =
            attackStart + duration;

        if (lastAttackSendTime >= attackStop)
        {
            NS_FATAL_ERROR(
                "Replay/Injection configuration invalid: all attackCount "
                "messages must be scheduled strictly before attackStop");
        }

        if (lastAttackSendTime >= simTime)
        {
            NS_FATAL_ERROR(
                "Replay/Injection attempts must finish before simTime");
        }
    }

    RngSeedManager::SetSeed(rngSeed);
    RngSeedManager::SetRun(run);

    g_payloadBytes = payloadBytes;
    g_publishInterval = Seconds(1.0 / publishRateHz);
    g_trafficStop = Seconds(trafficStop);
    g_attackStop = Seconds(attackStop);

    g_freshnessEnabled = freshness;
    g_authAclEnabled = authAcl;
    g_attackerAuthorized = attackerAuthorized;
    g_rateLimitingEnabled = rateLimiting;

    g_attackRateHz = attackRateHz;
    g_attackCount = attackCount;
    g_replaySequence = replaySequence;
    g_rateLimitHz = rateLimitHz;

    NodeContainer nodes;
    nodes.Create(4);

    Ptr<Node> publisher = nodes.Get(0);
    Ptr<Node> broker = nodes.Get(1);
    Ptr<Node> subscriber = nodes.Get(2);
    Ptr<Node> attackerNode = nodes.Get(3);

    CsmaHelper csma;

    std::ostringstream dataRate;
    dataRate << linkRateMbps << "Mbps";

    csma.SetChannelAttribute(
        "DataRate",
        StringValue(dataRate.str()));

    csma.SetChannelAttribute(
        "Delay",
        TimeValue(MicroSeconds(linkDelayUs)));

    NetDeviceContainer devices =
        csma.Install(nodes);

    InternetStackHelper internet;
    internet.Install(nodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase(
        "10.10.0.0",
        "255.255.255.0");

    Ipv4InterfaceContainer interfaces =
        ipv4.Assign(devices);

    g_publisherIp = interfaces.GetAddress(0);
    const Ipv4Address brokerIp = interfaces.GetAddress(1);
    g_subscriberIp = interfaces.GetAddress(2);
    g_attackerIp = interfaces.GetAddress(3);

    Ptr<Socket> brokerListenSocket =
        CreateListeningTcpSocket(
            broker,
            brokerIp,
            MQTT_PORT);

    g_subscriberSocket =
        Socket::CreateSocket(
            subscriber,
            TcpSocketFactory::GetTypeId());

    g_subscriberSocket->SetRecvCallback(
        MakeCallback(&HandleSubscriberRead));

    g_subscriberSocket->SetConnectCallback(
        MakeCallback(&SubscriberConnectSucceeded),
        MakeCallback(&SubscriberConnectFailed));

    if (g_subscriberSocket->Connect(
            InetSocketAddress(
                brokerIp,
                MQTT_PORT)) != 0)
    {
        NS_FATAL_ERROR("Subscriber TCP Connect() initiation failed");
    }

    g_publisherSocket =
        Socket::CreateSocket(
            publisher,
            TcpSocketFactory::GetTypeId());

    g_publisherSocket->SetRecvCallback(
        MakeCallback(&HandlePublisherRead));

    g_publisherSocket->SetConnectCallback(
        MakeCallback(&PublisherConnectSucceeded),
        MakeCallback(&PublisherConnectFailed));

    if (g_publisherSocket->Connect(
            InetSocketAddress(
                brokerIp,
                MQTT_PORT)) != 0)
    {
        NS_FATAL_ERROR("Publisher TCP Connect() initiation failed");
    }

    if (g_attackKind != AttackKind::NONE)
    {
        g_attackerSocket =
            Socket::CreateSocket(
                attackerNode,
                TcpSocketFactory::GetTypeId());

        g_attackerSocket->SetRecvCallback(
            MakeCallback(&HandleAttackerRead));

        g_attackerSocket->SetConnectCallback(
            MakeCallback(&AttackerConnectSucceeded),
            MakeCallback(&AttackerConnectFailed));

        if (g_attackerSocket->Connect(
                InetSocketAddress(
                    brokerIp,
                    MQTT_PORT)) != 0)
        {
            NS_FATAL_ERROR("Attacker TCP Connect() initiation failed");
        }
    }

    FlowMonitorHelper flowHelper;
    Ptr<FlowMonitor> monitor =
        flowHelper.InstallAll();

    Simulator::Schedule(
        Seconds(trafficStart),
        &SendLegitimatePublish);

    if (g_attackKind != AttackKind::NONE)
    {
        Simulator::Schedule(
            Seconds(attackStart),
            &SendAttackMessage);
    }

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    monitor->CheckForLostPackets();

    // -------------------------------------------------------------------------
    // FlowMonitor: network-level (IP) cross-check of the application-level
    // Counters above. Only flows destined for the broker are aggregated,
    // since that is the only node whose accept/reject decisions this project
    // studies.
    // -------------------------------------------------------------------------

    Ptr<Ipv4FlowClassifier> flowClassifier =
        DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> flowStatsMap =
        monitor->GetFlowStats();

    const Ipv4Address brokerFlowIp = interfaces.GetAddress(1);

    uint64_t flowTxPackets = 0;
    uint64_t flowRxPackets = 0;
    uint64_t flowLostPackets = 0;
    double flowDelaySumSeconds = 0.0;
    double flowJitterSumSeconds = 0.0;

    for (const auto& flowEntry : flowStatsMap)
    {
        const Ipv4FlowClassifier::FiveTuple flowTuple =
            flowClassifier->FindFlow(flowEntry.first);

        if (flowTuple.destinationAddress == brokerFlowIp)
        {
            flowTxPackets += flowEntry.second.txPackets;
            flowRxPackets += flowEntry.second.rxPackets;
            flowLostPackets += flowEntry.second.lostPackets;
            flowDelaySumSeconds += flowEntry.second.delaySum.GetSeconds();
            flowJitterSumSeconds += flowEntry.second.jitterSum.GetSeconds();
        }
    }

    const double flowMeanDelayMs =
        flowRxPackets > 0
            ? 1000.0 * flowDelaySumSeconds /
                  static_cast<double>(flowRxPackets)
            : 0.0;

    const double flowMeanJitterMs =
        flowRxPackets > 0
            ? 1000.0 * flowJitterSumSeconds /
                  static_cast<double>(flowRxPackets)
            : 0.0;

    // -------------------------------------------------------------------------
    // Metrics
    // -------------------------------------------------------------------------

    const uint64_t attackRejectedTotal =
        g_state.attackMessagesRejectedAuthAcl +
        g_state.attackMessagesRejectedFreshness +
        g_state.attackMessagesRateLimited;

    const double attackAcceptanceRatio =
        g_state.brokerAttackMessagesReceived > 0
            ? static_cast<double>(g_state.attackMessagesAccepted) /
              static_cast<double>(g_state.brokerAttackMessagesReceived)
            : 0.0;

    const double legitimateDeliveryRatio =
        g_state.publisherMessagesSent > 0
            ? static_cast<double>(
                  g_state.subscriberLegitimateMessagesReceived) /
              static_cast<double>(g_state.publisherMessagesSent)
            : 0.0;

    const double publisherMeanPubackDelayMs =
        g_state.publisherPubackDelaySamples > 0
            ? 1000.0 *
              g_state.publisherPubackDelaySumSeconds /
              static_cast<double>(
                  g_state.publisherPubackDelaySamples)
            : 0.0;

    const double legitimateMeanEndToEndDelayMs =
        g_state.legitimateEndToEndDelaySamples > 0
            ? 1000.0 *
              g_state.legitimateEndToEndDelaySumSeconds /
              static_cast<double>(
                  g_state.legitimateEndToEndDelaySamples)
            : 0.0;

    const double attackDuration =
        g_attackKind == AttackKind::DOS
            ? attackStop - attackStart
            : 0.0;

    const double realizedAttackRateHz =
        attackDuration > 0.0
            ? static_cast<double>(g_state.attackerMessagesSent) /
              attackDuration
            : 0.0;

    const double brokerForwardFailureRatio =
        g_state.brokerForwardSendAttempts > 0
            ? static_cast<double>(g_state.brokerForwardSendFailures) /
              static_cast<double>(g_state.brokerForwardSendAttempts)
            : 0.0;

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    const bool mqttHandshakeComplete =
        g_publisherMqttConnected &&
        g_subscriberMqttConnected &&
        g_subscriberSubscribed &&
        (
            (g_attackKind == AttackKind::NONE &&
             !g_attackerMqttConnected &&
             g_state.connackPacketsReceived == 2) ||
            (g_attackKind != AttackKind::NONE &&
             g_attackerMqttConnected &&
             g_state.connackPacketsReceived == 3)
        ) &&
        g_state.subackPacketsReceived == 1;

    const bool legitimateQos1Complete =
        g_state.publisherMessagesSent ==
            g_state.brokerLegitimateMessagesReceived &&
        g_state.publisherPubacksReceived ==
            g_state.publisherMessagesSent &&
        g_publisherPendingPubacks.empty();

    // Protocol-level metric only:
    // This means every attacker-originated QoS 1 PUBLISH received a PUBACK
    // from the broker. It does NOT mean the security pipeline accepted or
    // forwarded the attack.
    const bool attackerQos1Complete =
        g_attackKind == AttackKind::NONE
            ? (
                g_state.attackerMessagesSent == 0 &&
                g_state.attackerPubacksReceived == 0
              )
            : (
                g_state.attackerPubacksReceived ==
                    g_state.attackerMessagesSent
              );

    const bool attackAccountingConsistent =
        g_state.brokerAttackMessagesReceived ==
            g_state.attackMessagesAccepted +
            attackRejectedTotal &&
        g_state.brokerAttackMessagesReceived ==
            g_state.attackerMessagesSent;

    const uint64_t expectedForwardAttempts =
        g_state.brokerLegitimateMessagesReceived +
        g_state.attackMessagesAccepted;

    const bool forwardingAccountingConsistent =
        g_state.brokerForwardSendAttempts ==
            expectedForwardAttempts &&
        g_state.brokerForwardSendSuccess +
            g_state.brokerForwardSendFailures ==
            g_state.brokerForwardSendAttempts;

    const bool subscriberQos1Complete =
        g_state.subscriberPubacksSent ==
            g_state.subscriberMessagesReceived &&
        g_state.brokerSubscriberPubacksReceived ==
            g_state.subscriberPubacksSent &&
        g_brokerPendingPubacks.empty();

    const bool originalTrafficPreservedOrMeasured =
        g_state.subscriberLegitimateMessagesReceived <=
            g_state.publisherMessagesSent;

    // Expected security behavior for the selected isolated attack.
    bool securityBehaviorExpected = true;

    if (g_attackKind == AttackKind::REPLAY)
    {
        if (g_authAclEnabled && !g_attackerAuthorized)
        {
            securityBehaviorExpected =
                g_state.attackMessagesRejectedAuthAcl ==
                    g_state.attackerMessagesSent &&
                g_state.attackMessagesAccepted == 0;
        }
        else if (g_freshnessEnabled)
        {
            securityBehaviorExpected =
                g_state.attackMessagesRejectedFreshness ==
                    g_state.attackerMessagesSent &&
                g_state.attackMessagesAccepted == 0;
        }
        else
        {
            securityBehaviorExpected =
                g_state.attackMessagesAccepted ==
                    g_state.attackerMessagesSent;
        }
    }
    else if (g_attackKind == AttackKind::INJECTION)
    {
        if (g_authAclEnabled && !g_attackerAuthorized)
        {
            securityBehaviorExpected =
                g_state.attackMessagesRejectedAuthAcl ==
                    g_state.attackerMessagesSent &&
                g_state.attackMessagesAccepted == 0;
        }
        else
        {
            securityBehaviorExpected =
                g_state.attackMessagesAccepted ==
                    g_state.attackerMessagesSent;
        }
    }
    else if (g_attackKind == AttackKind::DOS)
    {
        if (g_authAclEnabled && !g_attackerAuthorized)
        {
            securityBehaviorExpected =
                g_state.attackMessagesRejectedAuthAcl ==
                    g_state.attackerMessagesSent;
        }
        else if (g_rateLimitingEnabled)
        {
            securityBehaviorExpected =
                g_state.attackMessagesRateLimited > 0 &&
                g_state.attackMessagesAccepted <
                    g_state.attackerMessagesSent;
        }
        else
        {
            securityBehaviorExpected =
                g_state.attackMessagesAccepted ==
                    g_state.attackerMessagesSent;
        }
    }
    else
    {
        securityBehaviorExpected =
            g_state.attackerMessagesSent == 0 &&
            g_state.brokerAttackMessagesReceived == 0;
    }

    // -------------------------------------------------------------------------
    // Structured JSON result
    // -------------------------------------------------------------------------

    std::cout
        << "{"

        << "\"scenario\":\"mqtt_qos1_security_game_wire\","
        << "\"rng_seed\":" << rngSeed << ","
        << "\"run\":" << run << ","

        << "\"configuration\":{"
        << "\"transport\":\"TCP\","
        << "\"mqtt_version\":\"3.1.1\","
        << "\"mqtt_qos\":1,"
        << "\"mqtt_wire_encoder\":true,"
        << "\"attack\":\""
        << AttackKindToString(g_attackKind) << "\","
        << "\"freshness_enabled\":"
        << BoolJson(freshness) << ","
        << "\"auth_acl_enabled\":"
        << BoolJson(authAcl) << ","
        << "\"attacker_authorized\":"
        << BoolJson(attackerAuthorized) << ","
        << "\"rate_limiting_enabled\":"
        << BoolJson(rateLimiting) << ","
        << "\"security_pipeline\":\"auth_acl->freshness->rate_limiting->forwarding\","
        << "\"topic\":\"" << MQTT_TOPIC << "\","
        << "\"link_rate_mbps\":"
        << linkRateMbps << ","
        << "\"link_delay_us\":"
        << linkDelayUs << ","
        << "\"application_data_bytes\":"
        << payloadBytes << ","
        << "\"research_metadata_bytes\":12,"
        << "\"publish_rate_hz\":"
        << publishRateHz << ","
        << "\"attack_rate_hz\":"
        << attackRateHz << ","
        << "\"attack_count\":"
        << attackCount << ","
        << "\"replay_sequence\":"
        << replaySequence << ","
        << "\"rate_limit_hz\":"
        << rateLimitHz << ","
        << "\"attack_start_s\":"
        << attackStart << ","
        << "\"attack_stop_s\":"
        << attackStop << ","
        << "\"traffic_stop_s\":"
        << trafficStop << ","
        << "\"drain_period_s\":"
        << (simTime - trafficStop) << ","
        << "\"sim_time_s\":"
        << simTime
        << "},"

        << "\"mqtt_control_packets\":{"
        << "\"connect_sent\":"
        << g_state.connectPacketsSent << ","
        << "\"connack_sent\":"
        << g_state.connackPacketsSent << ","
        << "\"connack_received\":"
        << g_state.connackPacketsReceived << ","
        << "\"subscribe_sent\":"
        << g_state.subscribePacketsSent << ","
        << "\"suback_sent\":"
        << g_state.subackPacketsSent << ","
        << "\"suback_received\":"
        << g_state.subackPacketsReceived
        << "},"

        << "\"attack_state\":{"
        << "\"attacker_messages_sent\":"
        << g_state.attackerMessagesSent << ","
        << "\"attacker_pubacks_received\":"
        << g_state.attackerPubacksReceived << ","
        << "\"broker_attack_messages_received\":"
        << g_state.brokerAttackMessagesReceived << ","
        << "\"attack_messages_accepted\":"
        << g_state.attackMessagesAccepted << ","
        << "\"attack_rejected_auth_acl\":"
        << g_state.attackMessagesRejectedAuthAcl << ","
        << "\"attack_rejected_freshness\":"
        << g_state.attackMessagesRejectedFreshness << ","
        << "\"attack_rate_limited\":"
        << g_state.attackMessagesRateLimited << ","
        << "\"subscriber_attack_messages_received\":"
        << g_state.subscriberAttackMessagesReceived
        << "},"

        << "\"application_state\":{"
        << "\"publisher_messages_sent\":"
        << g_state.publisherMessagesSent << ","
        << "\"publisher_pubacks_received\":"
        << g_state.publisherPubacksReceived << ","
        << "\"broker_legitimate_messages_received\":"
        << g_state.brokerLegitimateMessagesReceived << ","
        << "\"broker_pubacks_sent\":"
        << g_state.brokerPubacksSent << ","
        << "\"broker_forward_send_attempts\":"
        << g_state.brokerForwardSendAttempts << ","
        << "\"broker_forward_send_success\":"
        << g_state.brokerForwardSendSuccess << ","
        << "\"broker_forward_send_failures\":"
        << g_state.brokerForwardSendFailures << ","
        << "\"broker_legitimate_forward_send_success\":"
        << g_state.brokerLegitimateForwardSendSuccess << ","
        << "\"broker_attack_forward_send_success\":"
        << g_state.brokerAttackForwardSendSuccess << ","
        << "\"subscriber_messages_received\":"
        << g_state.subscriberMessagesReceived << ","
        << "\"subscriber_legitimate_messages_received\":"
        << g_state.subscriberLegitimateMessagesReceived << ","
        << "\"subscriber_pubacks_sent\":"
        << g_state.subscriberPubacksSent << ","
        << "\"broker_subscriber_pubacks_received\":"
        << g_state.brokerSubscriberPubacksReceived << ","
        << "\"malformed_packets\":"
        << g_state.malformedPackets << ","
        << "\"unexpected_packets\":"
        << g_state.unexpectedPackets
        << "},"

        << "\"monitoring\":{"
        << "\"attack_acceptance_ratio\":"
        << attackAcceptanceRatio << ","
        << "\"legitimate_delivery_ratio\":"
        << legitimateDeliveryRatio << ","
        << "\"publisher_mean_puback_delay_ms\":"
        << publisherMeanPubackDelayMs << ","
        << "\"legitimate_mean_end_to_end_delay_ms\":"
        << legitimateMeanEndToEndDelayMs << ","
        << "\"broker_forward_failure_ratio\":"
        << brokerForwardFailureRatio << ","
        << "\"realized_attack_rate_hz\":"
        << realizedAttackRateHz
        << "},"

        << "\"flow_monitor\":{"
        << "\"tx_packets\":"
        << flowTxPackets << ","
        << "\"rx_packets\":"
        << flowRxPackets << ","
        << "\"lost_packets\":"
        << flowLostPackets << ","
        << "\"mean_delay_ms\":"
        << flowMeanDelayMs << ","
        << "\"mean_jitter_ms\":"
        << flowMeanJitterMs
        << "},"

        << "\"validation\":{"
        << "\"mqtt_handshake_complete\":"
        << BoolJson(mqttHandshakeComplete) << ","
        << "\"legitimate_qos1_complete\":"
        << BoolJson(legitimateQos1Complete) << ","
        << "\"attacker_qos1_complete\":"
        << BoolJson(attackerQos1Complete) << ","
        << "\"attack_accounting_consistent\":"
        << BoolJson(attackAccountingConsistent) << ","
        << "\"forwarding_accounting_consistent\":"
        << BoolJson(forwardingAccountingConsistent) << ","
        << "\"subscriber_qos1_complete\":"
        << BoolJson(subscriberQos1Complete) << ","
        << "\"security_behavior_expected\":"
        << BoolJson(securityBehaviorExpected) << ","
        << "\"original_traffic_preserved_or_measured\":"
        << BoolJson(originalTrafficPreservedOrMeasured) << ","
        << "\"no_malformed_packets\":"
        << BoolJson(g_state.malformedPackets == 0) << ","
        << "\"no_unexpected_packets\":"
        << BoolJson(g_state.unexpectedPackets == 0)
        << "}"

        << "}"
        << std::endl;

    Simulator::Destroy();
    return 0;
}
