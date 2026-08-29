#include "mqtt-wire.h"

#include "ns3/core-module.h" // NS_FATAL_ERROR

using namespace ns3;

namespace Mqtt
{

namespace
{

void
AppendU16(std::vector<uint8_t>& out, uint16_t value)
{
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(value & 0xff));
}

uint16_t
ReadU16(const uint8_t* p)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(p[0]) << 8) |
        static_cast<uint16_t>(p[1]));
}

void
AppendUtf8(std::vector<uint8_t>& out, const std::string& text)
{
    if (text.size() > 65535)
    {
        NS_FATAL_ERROR("MQTT UTF-8 string exceeds 65535 bytes");
    }

    AppendU16(out, static_cast<uint16_t>(text.size()));
    out.insert(out.end(), text.begin(), text.end());
}

void
AppendRemainingLength(std::vector<uint8_t>& out, uint32_t value)
{
    // MQTT Remaining Length uses a variable-byte integer with at most 4 bytes.
    do
    {
        uint8_t encoded = static_cast<uint8_t>(value % 128);
        value /= 128;

        if (value > 0)
        {
            encoded |= 0x80;
        }

        out.push_back(encoded);
    }
    while (value > 0);
}

bool
DecodeRemainingLength(const std::vector<uint8_t>& buffer,
                      size_t offset,
                      uint32_t& remainingLength,
                      size_t& encodedBytes)
{
    remainingLength = 0;
    encodedBytes = 0;

    uint32_t multiplier = 1;

    while (true)
    {
        if (offset + encodedBytes >= buffer.size())
        {
            return false; // incomplete TCP stream
        }

        if (encodedBytes >= 4)
        {
            NS_FATAL_ERROR("Malformed MQTT Remaining Length");
        }

        const uint8_t byte = buffer[offset + encodedBytes];

        remainingLength +=
            static_cast<uint32_t>(byte & 0x7f) * multiplier;

        ++encodedBytes;

        if ((byte & 0x80) == 0)
        {
            return true;
        }

        multiplier *= 128;
    }
}

} // namespace

Ptr<Packet>
ToNs3Packet(const std::vector<uint8_t>& bytes)
{
    if (bytes.empty())
    {
        return Create<Packet>();
    }

    return Create<Packet>(bytes.data(), bytes.size());
}

std::vector<uint8_t>
BuildConnect(const std::string& clientId)
{
    std::vector<uint8_t> body;

    // Variable header: Protocol Name = "MQTT", Protocol Level = 4 (3.1.1),
    // Connect Flags = Clean Session, Keep Alive = 60 seconds.
    AppendUtf8(body, "MQTT");
    body.push_back(0x04);
    body.push_back(0x02);
    AppendU16(body, 60);

    // Payload: Client Identifier.
    AppendUtf8(body, clientId);

    std::vector<uint8_t> packet;
    packet.push_back(0x10); // CONNECT
    AppendRemainingLength(packet, static_cast<uint32_t>(body.size()));
    packet.insert(packet.end(), body.begin(), body.end());

    return packet;
}

std::vector<uint8_t>
BuildConnAck()
{
    return {0x20, 0x02, 0x00, 0x00};
}

std::vector<uint8_t>
BuildPublishQos1(const std::string& topic,
                 uint16_t packetId,
                 const std::vector<uint8_t>& payload,
                 bool dup,
                 bool retain)
{
    if (packetId == 0)
    {
        NS_FATAL_ERROR("QoS 1 PUBLISH requires non-zero Packet Identifier");
    }

    std::vector<uint8_t> body;

    AppendUtf8(body, topic);
    AppendU16(body, packetId);
    body.insert(body.end(), payload.begin(), payload.end());

    // Packet type 3, DUP in bit 3, QoS=1 in bits 2..1, RETAIN in bit 0.
    uint8_t header = 0x30 | 0x02;

    if (dup)
    {
        header |= 0x08;
    }

    if (retain)
    {
        header |= 0x01;
    }

    std::vector<uint8_t> packet;
    packet.push_back(header);
    AppendRemainingLength(packet, static_cast<uint32_t>(body.size()));
    packet.insert(packet.end(), body.begin(), body.end());

    return packet;
}

std::vector<uint8_t>
BuildPubAck(uint16_t packetId)
{
    if (packetId == 0)
    {
        NS_FATAL_ERROR("PUBACK requires non-zero Packet Identifier");
    }

    return {
        0x40,
        0x02,
        static_cast<uint8_t>((packetId >> 8) & 0xff),
        static_cast<uint8_t>(packetId & 0xff)
    };
}

std::vector<uint8_t>
BuildSubscribe(const std::string& topicFilter,
               uint16_t packetId,
               uint8_t requestedQos)
{
    if (packetId == 0)
    {
        NS_FATAL_ERROR("SUBSCRIBE requires non-zero Packet Identifier");
    }

    if (requestedQos > 2)
    {
        NS_FATAL_ERROR("Invalid requested QoS");
    }

    std::vector<uint8_t> body;
    AppendU16(body, packetId);
    AppendUtf8(body, topicFilter);
    body.push_back(requestedQos);

    std::vector<uint8_t> packet;
    packet.push_back(0x82); // SUBSCRIBE requires reserved flags 0010
    AppendRemainingLength(packet, static_cast<uint32_t>(body.size()));
    packet.insert(packet.end(), body.begin(), body.end());

    return packet;
}

std::vector<uint8_t>
BuildSubAck(uint16_t packetId, uint8_t grantedQos)
{
    if (packetId == 0)
    {
        NS_FATAL_ERROR("SUBACK requires non-zero Packet Identifier");
    }

    std::vector<uint8_t> body;
    AppendU16(body, packetId);
    body.push_back(grantedQos);

    std::vector<uint8_t> packet;
    packet.push_back(0x90);
    AppendRemainingLength(packet, static_cast<uint32_t>(body.size()));
    packet.insert(packet.end(), body.begin(), body.end());

    return packet;
}

bool
TryExtractPacket(std::vector<uint8_t>& stream, PacketView& out)
{
    if (stream.size() < 2)
    {
        return false;
    }

    uint32_t remainingLength = 0;
    size_t remainingLengthBytes = 0;

    if (!DecodeRemainingLength(
            stream,
            1,
            remainingLength,
            remainingLengthBytes))
    {
        return false;
    }

    const size_t fixedHeaderBytes = 1 + remainingLengthBytes;
    const size_t fullPacketBytes = fixedHeaderBytes + remainingLength;

    if (stream.size() < fullPacketBytes)
    {
        return false;
    }

    out.header = stream[0];
    out.type = static_cast<uint8_t>((stream[0] >> 4) & 0x0f);
    out.body.assign(
        stream.begin() + fixedHeaderBytes,
        stream.begin() + fullPacketBytes);

    stream.erase(stream.begin(), stream.begin() + fullPacketBytes);
    return true;
}

PublishView
ParsePublish(const PacketView& packet)
{
    PublishView result;

    if (packet.type != static_cast<uint8_t>(Type::PUBLISH))
    {
        return result;
    }

    result.dup = (packet.header & 0x08) != 0;
    result.qos = static_cast<uint8_t>((packet.header >> 1) & 0x03);
    result.retain = (packet.header & 0x01) != 0;

    if (result.qos != 1)
    {
        return result;
    }

    if (packet.body.size() < 4)
    {
        return result;
    }

    const uint16_t topicLength = ReadU16(packet.body.data());

    if (topicLength == 0)
    {
        return result;
    }

    const size_t packetIdOffset = 2 + topicLength;

    if (packet.body.size() < packetIdOffset + 2)
    {
        return result;
    }

    result.topic.assign(
        packet.body.begin() + 2,
        packet.body.begin() + 2 + topicLength);

    result.packetId =
        ReadU16(packet.body.data() + packetIdOffset);

    if (result.packetId == 0)
    {
        return result;
    }

    result.payload.assign(
        packet.body.begin() + packetIdOffset + 2,
        packet.body.end());

    result.valid = true;
    return result;
}

bool
ParsePacketIdentifier(const PacketView& packet, uint16_t& packetId)
{
    if (packet.body.size() < 2)
    {
        return false;
    }

    packetId = ReadU16(packet.body.data());
    return packetId != 0;
}

bool
ParseSubscribe(const PacketView& packet,
               uint16_t& packetId,
               std::string& topicFilter,
               uint8_t& requestedQos)
{
    if (packet.type != static_cast<uint8_t>(Type::SUBSCRIBE))
    {
        return false;
    }

    if ((packet.header & 0x0f) != 0x02)
    {
        return false;
    }

    if (packet.body.size() < 5)
    {
        return false;
    }

    packetId = ReadU16(packet.body.data());

    if (packetId == 0)
    {
        return false;
    }

    const uint16_t topicLength =
        ReadU16(packet.body.data() + 2);

    if (topicLength == 0 ||
        packet.body.size() < static_cast<size_t>(4 + topicLength + 1))
    {
        return false;
    }

    topicFilter.assign(
        packet.body.begin() + 4,
        packet.body.begin() + 4 + topicLength);

    requestedQos = packet.body[4 + topicLength];

    return requestedQos <= 2;
}

} // namespace Mqtt
