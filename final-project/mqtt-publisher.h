#ifndef MQTT_PUBLISHER_H
#define MQTT_PUBLISHER_H

#include "ns3/core-module.h"
#include "ns3/network-module.h"

// =============================================================================
// Publisher
// =============================================================================
//
// Represents the legitimate industrial IoT device (e.g. a sensor sending
// telemetry at a fixed rate). Its only job is to generate baseline traffic
// with no awareness of the active attack or defense configuration, so the
// impact of attack/defense combinations can be measured against it.
// =============================================================================

void PublisherConnectSucceeded(ns3::Ptr<ns3::Socket> socket);
void PublisherConnectFailed(ns3::Ptr<ns3::Socket> socket);

void HandlePublisherRead(ns3::Ptr<ns3::Socket> socket);

// Self-rescheduling via Simulator::Schedule: sends one PUBLISH every
// g_publishInterval until g_trafficStop, then stops rescheduling itself.
void SendLegitimatePublish();

#endif // MQTT_PUBLISHER_H
