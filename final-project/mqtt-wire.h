#ifndef MQTT_WIRE_H
#define MQTT_WIRE_H

#include <cstdint>
#include <string>
#include <vector>

// Pulled in as broad module headers (matching the original file's include
// style) rather than narrow ones, since the exact narrow header paths for
// Ptr<Packet> are not something I want to guess at — see chat note.
#include "ns3/core-module.h"
#include "ns3/network-module.h"

// =============================================================================
// MQTT 3.1.1 wire-format layer
// =============================================================================
//
// This namespace has exactly one responsibility: speaking MQTT over raw TCP
// bytes. It intentionally contains no security or research logic, so that
// changes to security policy (Broker module) never require touching how
// bytes are encoded, and vice versa.
//
// Scope: this implements only the packet types this experiment needs
// (CONNECT, CONNACK, PUBLISH, PUBACK, SUBSCRIBE, SUBACK) for QoS 1. It is not
// a complete MQTT 3.1.1 broker: session persistence, retained messages,
// wildcards, QoS 0/2, and reconnection/retransmission handling are out of
// scope.
// =============================================================================

namespace Mqtt
{

enum class Type : uint8_t
{
    CONNECT = 1,
    CONNACK = 2,
    PUBLISH = 3,
    PUBACK = 4,
    SUBSCRIBE = 8,
    SUBACK = 9
};

struct PacketView
{
    uint8_t header{0};
    uint8_t type{0};
    std::vector<uint8_t> body;
};

struct PublishView
{
    bool valid{false};
    bool dup{false};
    uint8_t qos{0};
    bool retain{false};
    std::string topic;
    uint16_t packetId{0};
    std::vector<uint8_t> payload;
};

// Converts a raw byte buffer into an ns-3 Packet suitable for socket Send().
ns3::Ptr<ns3::Packet> ToNs3Packet(const std::vector<uint8_t>& bytes);

// --- Packet builders ---------------------------------------------------

std::vector<uint8_t> BuildConnect(const std::string& clientId);
std::vector<uint8_t> BuildConnAck();

std::vector<uint8_t> BuildPublishQos1(const std::string& topic,
                                      uint16_t packetId,
                                      const std::vector<uint8_t>& payload,
                                      bool dup = false,
                                      bool retain = false);

std::vector<uint8_t> BuildPubAck(uint16_t packetId);

std::vector<uint8_t> BuildSubscribe(const std::string& topicFilter,
                                    uint16_t packetId,
                                    uint8_t requestedQos);

std::vector<uint8_t> BuildSubAck(uint16_t packetId, uint8_t grantedQos);

// --- Parsers -------------------------------------------------------------

// TCP stream reassembly: extracts one complete MQTT packet from `stream` if
// one is fully present, removing its bytes from `stream`. Returns false
// (leaving `stream` untouched) if the buffer does not yet hold a full
// packet, so the caller can wait for more bytes.
bool TryExtractPacket(std::vector<uint8_t>& stream, PacketView& out);

PublishView ParsePublish(const PacketView& packet);

bool ParsePacketIdentifier(const PacketView& packet, uint16_t& packetId);

bool ParseSubscribe(const PacketView& packet,
                    uint16_t& packetId,
                    std::string& topicFilter,
                    uint8_t& requestedQos);

} // namespace Mqtt

#endif // MQTT_WIRE_H
