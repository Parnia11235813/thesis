#ifndef MQTT_BROKER_H
#define MQTT_BROKER_H

#include <cstdint>

#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"

// =============================================================================
// Broker
// =============================================================================
//
// This is where the security game is actually played. Auth/ACL, Freshness,
// and Rate Limiting are implemented here as a sequential pipeline that
// decides whether a received PUBLISH is forwarded to the subscriber. The
// module deliberately separates "wire-level acknowledgement" (does the
// sender get a PUBACK?) from "security policy" (does the message actually
// get published?) — attacker_pubacks_received is therefore a wire-health
// metric, not a measure of attack success.
//
// Only CreateListeningTcpSocket is exposed; everything else (accept
// classification, the security pipeline, forwarding, and TCP reassembly) is
// an internal implementation detail wired up through ns-3 callbacks.
// =============================================================================

ns3::Ptr<ns3::Socket> CreateListeningTcpSocket(ns3::Ptr<ns3::Node> node,
                                               ns3::Ipv4Address address,
                                               uint16_t port);

#endif // MQTT_BROKER_H
