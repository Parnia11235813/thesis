#ifndef MQTT_SUBSCRIBER_H
#define MQTT_SUBSCRIBER_H

#include "ns3/core-module.h"
#include "ns3/network-module.h"

// =============================================================================
// Subscriber
// =============================================================================
//
// The end of the delivery chain, and also the final measurement endpoint:
// only here can we tell whether a message was actually delivered end to end.
// =============================================================================

void SubscriberConnectSucceeded(ns3::Ptr<ns3::Socket> socket);
void SubscriberConnectFailed(ns3::Ptr<ns3::Socket> socket);

void HandleSubscriberRead(ns3::Ptr<ns3::Socket> socket);

#endif // MQTT_SUBSCRIBER_H
