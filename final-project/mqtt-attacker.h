#ifndef MQTT_ATTACKER_H
#define MQTT_ATTACKER_H

#include "ns3/core-module.h"
#include "ns3/network-module.h"

// =============================================================================
// Attacker
// =============================================================================
//
// Generates all three attack scenarios (Replay / Injection / DoS) from a
// single SendAttackMessage() entry point that branches on g_attackKind, so
// the three attacks share connection/PacketId/send infrastructure and differ
// only in payload content and scheduling — keeping them directly comparable
// in the results.
// =============================================================================

void AttackerConnectSucceeded(ns3::Ptr<ns3::Socket> socket);
void AttackerConnectFailed(ns3::Ptr<ns3::Socket> socket);

void HandleAttackerRead(ns3::Ptr<ns3::Socket> socket);

// Self-rescheduling via Simulator::Schedule: branches on g_attackKind to
// produce Replay, Injection, or DoS traffic until the relevant stop
// condition (g_attackStop, or g_attackCount attempts) is reached.
void SendAttackMessage();

#endif // MQTT_ATTACKER_H
