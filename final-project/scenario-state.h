#ifndef SCENARIO_STATE_H
#define SCENARIO_STATE_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"

// =============================================================================
// Unified MQTT security-game scenario state
// =============================================================================
//
// This module holds the "definition of the game": which attack is active,
// which defenses are enabled, and where the counters live. In Stackelberg
// terms, this is where the defender strategy (which defenses are on) and the
// attacker strategy (which attack kind) are injected as parameters.
//
// Every other module (Publisher, Attacker, Subscriber, Broker, main) reads
// and/or writes this shared state; this module has no dependency on any of
// them (it does not include mqtt-wire.h or research-payload.h).
//
// Connection classification is determined once at TCP accept time and
// stored per broker-side socket (g_brokerClientRole) — see the Broker
// module. Security decisions therefore never rely on application payload
// content for deciding whether a connection is the attacker.
//
// When --attack=none, the attacker never establishes a TCP/MQTT connection;
// the clean baseline therefore contains only Publisher, Broker, and
// Subscriber MQTT traffic (this is enforced in main, not here).
// =============================================================================

constexpr uint16_t MQTT_PORT = 1883;
constexpr uint32_t LEGITIMATE_PUBLISHER_ID = 1;
constexpr uint32_t INJECTION_PUBLISHER_ID = 999;

extern const std::string MQTT_TOPIC;

// --- Attack kind -------------------------------------------------------------

enum class AttackKind
{
    NONE,
    REPLAY,
    INJECTION,
    DOS
};

AttackKind ParseAttackKind(const std::string& value);
std::string AttackKindToString(AttackKind kind);

// --- Broker-side connection classification -----------------------------------

enum class ClientRole
{
    UNKNOWN,
    PUBLISHER,
    SUBSCRIBER,
    ATTACKER
};

// --- Counters ------------------------------------------------------------------
//
// Tracks the full lifecycle of every message (send -> broker receive ->
// accept/reject -> forward -> subscriber receive -> PUBACK). This is what
// the final JSON output and main's internal consistency checks are built
// from.

struct Counters
{
    uint64_t connectPacketsSent{0};
    uint64_t connackPacketsSent{0};
    uint64_t connackPacketsReceived{0};

    uint64_t subscribePacketsSent{0};
    uint64_t subackPacketsSent{0};
    uint64_t subackPacketsReceived{0};

    uint64_t publisherMessagesSent{0};
    uint64_t publisherPubacksReceived{0};

    uint64_t attackerMessagesSent{0};
    uint64_t attackerPubacksReceived{0};

    uint64_t brokerLegitimateMessagesReceived{0};
    uint64_t brokerAttackMessagesReceived{0};

    uint64_t attackMessagesAccepted{0};
    uint64_t attackMessagesRejectedAuthAcl{0};
    uint64_t attackMessagesRejectedFreshness{0};
    uint64_t attackMessagesRateLimited{0};

    uint64_t brokerPubacksSent{0};

    uint64_t brokerForwardSendAttempts{0};
    uint64_t brokerForwardSendSuccess{0};
    uint64_t brokerForwardSendFailures{0};

    uint64_t brokerLegitimateForwardSendSuccess{0};
    uint64_t brokerAttackForwardSendSuccess{0};

    uint64_t subscriberMessagesReceived{0};
    uint64_t subscriberLegitimateMessagesReceived{0};
    uint64_t subscriberAttackMessagesReceived{0};
    uint64_t subscriberPubacksSent{0};
    uint64_t brokerSubscriberPubacksReceived{0};

    uint64_t malformedPackets{0};
    uint64_t unexpectedPackets{0};

    double publisherPubackDelaySumSeconds{0.0};
    uint64_t publisherPubackDelaySamples{0};

    double legitimateEndToEndDelaySumSeconds{0.0};
    uint64_t legitimateEndToEndDelaySamples{0};
};

extern Counters g_state;

// --- Sockets and identities ----------------------------------------------------

extern ns3::Ptr<ns3::Socket> g_publisherSocket;
extern ns3::Ptr<ns3::Socket> g_attackerSocket;
extern ns3::Ptr<ns3::Socket> g_subscriberSocket;
extern ns3::Ptr<ns3::Socket> g_brokerSubscriberSocket;

extern ns3::Ipv4Address g_publisherIp;
extern ns3::Ipv4Address g_attackerIp;
extern ns3::Ipv4Address g_subscriberIp;

// --- Scenario configuration (set from CLI in main) ------------------------------

extern uint32_t g_payloadBytes;
extern uint64_t g_nextLegitSequence;
extern uint64_t g_nextAttackSequence;

extern uint16_t g_nextPublisherPacketId;
extern uint16_t g_nextAttackerPacketId;
extern uint16_t g_nextBrokerPacketId;

extern bool g_publisherMqttConnected;
extern bool g_attackerMqttConnected;
extern bool g_subscriberMqttConnected;
extern bool g_subscriberSubscribed;

extern ns3::Time g_publishInterval;
extern ns3::Time g_trafficStop;
extern ns3::Time g_attackStop;

extern AttackKind g_attackKind;

extern bool g_freshnessEnabled;
extern bool g_authAclEnabled;
extern bool g_attackerAuthorized;
extern bool g_rateLimitingEnabled;

extern double g_attackRateHz;
extern double g_rateLimitHz;

extern uint32_t g_attackCount;
extern uint32_t g_attackMessagesScheduled;

extern uint64_t g_replaySequence;
extern bool g_replayPayloadCaptured;
extern std::vector<uint8_t> g_capturedReplayPayload;

// Highest accepted application sequence per publisher.
// This is research-layer freshness state, not MQTT QoS state.
extern std::map<uint32_t, uint64_t> g_highestAcceptedSequence;

// Fixed one-second rate-limit window state.
extern int64_t g_currentRateWindow;
extern uint64_t g_rateWindowAccepted;

// --- Per-socket TCP reassembly buffers -------------------------------------------

extern std::map<ns3::Ptr<ns3::Socket>, std::vector<uint8_t>> g_brokerBuffers;
extern std::vector<uint8_t> g_publisherBuffer;
extern std::vector<uint8_t> g_attackerBuffer;
extern std::vector<uint8_t> g_subscriberBuffer;

extern std::map<ns3::Ptr<ns3::Socket>, ClientRole> g_brokerClientRole;
extern std::map<ns3::Ptr<ns3::Socket>, bool> g_brokerClientConnected;

// Publisher Packet Identifier -> original publish timestamp.
extern std::map<uint16_t, double> g_publisherPendingPubacks;

// Sequence -> original publisher send timestamp.
extern std::map<uint64_t, double> g_legitimateSendTimes;

// Broker Packet Identifier -> true if original legitimate; false if
// attack-originated. This is the broker's internal "ground truth" that the
// Subscriber module reads instead of trusting the payload's publisherId.
extern std::map<uint16_t, bool> g_brokerPendingPubacks;

// --- Shared helpers ---------------------------------------------------------------

uint16_t NextPacketId(uint16_t& state);

std::string BoolJson(bool value);

// Fixed one-second-window rate limiter. Only meaningful for isAttack=true;
// legitimate traffic is never rate-limited in this isolated scenario.
bool RateLimitAccept(bool isAttack);

#endif // SCENARIO_STATE_H
