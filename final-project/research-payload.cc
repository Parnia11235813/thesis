#include "research-payload.h"

namespace
{

void
WriteU32(std::vector<uint8_t>& out, uint32_t value)
{
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(value & 0xff));
}

void
WriteU64(std::vector<uint8_t>& out, uint64_t value)
{
    for (int shift = 56; shift >= 0; shift -= 8)
    {
        out.push_back(static_cast<uint8_t>((value >> shift) & 0xff));
    }
}

uint32_t
ReadU32(const uint8_t* p)
{
    return
        (static_cast<uint32_t>(p[0]) << 24) |
        (static_cast<uint32_t>(p[1]) << 16) |
        (static_cast<uint32_t>(p[2]) << 8) |
        static_cast<uint32_t>(p[3]);
}

uint64_t
ReadU64(const uint8_t* p)
{
    uint64_t value = 0;

    for (int i = 0; i < 8; ++i)
    {
        value = (value << 8) | static_cast<uint64_t>(p[i]);
    }

    return value;
}

} // namespace

std::vector<uint8_t>
CreateResearchPayload(uint32_t publisherId,
                      uint64_t sequence,
                      uint32_t payloadBytes)
{
    std::vector<uint8_t> payload;
    payload.reserve(12 + payloadBytes);

    WriteU32(payload, publisherId);
    WriteU64(payload, sequence);

    for (uint32_t i = 0; i < payloadBytes; ++i)
    {
        payload.push_back(static_cast<uint8_t>(i & 0xff));
    }

    return payload;
}

bool
ParseResearchPayload(const std::vector<uint8_t>& payload,
                     uint32_t& publisherId,
                     uint64_t& sequence)
{
    if (payload.size() < 12)
    {
        return false;
    }

    publisherId = ReadU32(payload.data());
    sequence = ReadU64(payload.data() + 4);
    return true;
}
