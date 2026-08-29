#include "scenario-state.h"

#include <cmath>

#include "ns3/core-module.h" // NS_FATAL_ERROR, Simulator

using namespace ns3;

const std::string MQTT_TOPIC = "factory/sensor/telemetry";

AttackKind
ParseAttackKind(const std::string& value)
{
    if (value == "none")
    {
        return AttackKind::NONE;
    }
    if (value == "replay")
    {
        return AttackKind::REPLAY;
    }
    if (value == "injection")
    {
        return AttackKind::INJECTION;
    }
    if (value == "dos")
    {
        return AttackKind::DOS;
    }

    NS_FATAL_ERROR("Invalid --attack value. Use none|replay|injection|dos");
    return AttackKind::NONE;
}

std::string
AttackKindToString(AttackKind kind)
{
    switch (kind)
    {
    case AttackKind::NONE:
        return "none";
    case AttackKind::REPLAY:
        return "replay";
    case AttackKind::INJECTION:
        return "injection";
    case AttackKind::DOS:
        return "dos";
    }

    return "unknown";
}

Counters g_state;

Ptr<Socket> g_publisherSocket;
Ptr<Socket> g_attackerSocket;
Ptr<Socket> g_subscriberSocket;
Ptr<Socket> g_brokerSubscriberSocket;

Ipv4Address g_publisherIp;
Ipv4Address g_attackerIp;
Ipv4Address g_subscriberIp;

uint32_t g_payloadBytes = 256;
uint64_t g_nextLegitSequence = 1;
uint64_t g_nextAttackSequence = 1;

uint16_t g_nextPublisherPacketId = 1;
uint16_t g_nextAttackerPacketId = 1;
uint16_t g_nextBrokerPacketId = 1;

bool g_publisherMqttConnected = false;
bool g_attackerMqttConnected = false;
bool g_subscriberMqttConnected = false;
bool g_subscriberSubscribed = false;

Time g_publishInterval = MilliSeconds(50);
Time g_trafficStop = Seconds(11);
Time g_attackStop = Seconds(8);

AttackKind g_attackKind = AttackKind::NONE;

bool g_freshnessEnabled = false;
bool g_authAclEnabled = false;
bool g_attackerAuthorized = false;
bool g_rateLimitingEnabled = false;

double g_attackRateHz = 100.0;
double g_rateLimitHz = 50.0;

uint32_t g_attackCount = 20;
uint32_t g_attackMessagesScheduled = 0;

uint64_t g_replaySequence = 1;
bool g_replayPayloadCaptured = false;
std::vector<uint8_t> g_capturedReplayPayload;

std::map<uint32_t, uint64_t> g_highestAcceptedSequence;

int64_t g_currentRateWindow = -1;
uint64_t g_rateWindowAccepted = 0;

std::map<Ptr<Socket>, std::vector<uint8_t>> g_brokerBuffers;
std::vector<uint8_t> g_publisherBuffer;
std::vector<uint8_t> g_attackerBuffer;
std::vector<uint8_t> g_subscriberBuffer;

std::map<Ptr<Socket>, ClientRole> g_brokerClientRole;
std::map<Ptr<Socket>, bool> g_brokerClientConnected;

std::map<uint16_t, double> g_publisherPendingPubacks;
std::map<uint64_t, double> g_legitimateSendTimes;
std::map<uint16_t, bool> g_brokerPendingPubacks;

uint16_t
NextPacketId(uint16_t& state)
{
    if (state == 0)
    {
        state = 1;
    }

    const uint16_t result = state;

    ++state;

    if (state == 0)
    {
        state = 1;
    }

    return result;
}

std::string
BoolJson(bool value)
{
    return value ? "true" : "false";
}

bool
RateLimitAccept(bool isAttack)
{
    if (!isAttack || !g_rateLimitingEnabled)
    {
        return true;
    }

    if (g_rateLimitHz <= 0.0)
    {
        return false;
    }

    const double nowSeconds = Simulator::Now().GetSeconds();
    const int64_t windowIndex =
        static_cast<int64_t>(std::floor(nowSeconds));

    if (windowIndex != g_currentRateWindow)
    {
        g_currentRateWindow = windowIndex;
        g_rateWindowAccepted = 0;
    }

    const uint64_t maxAcceptedPerWindow =
        static_cast<uint64_t>(std::floor(g_rateLimitHz));

    if (g_rateWindowAccepted < maxAcceptedPerWindow)
    {
        ++g_rateWindowAccepted;
        return true;
    }

    return false;
}
