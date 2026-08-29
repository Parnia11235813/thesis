#ifndef RESEARCH_PAYLOAD_H
#define RESEARCH_PAYLOAD_H

#include <cstdint>
#include <vector>

// =============================================================================
// Research payload
// =============================================================================
//
// MQTT payload layout used by the experiment:
//   4 bytes publisher_id
//   8 bytes sequence
//   N bytes deterministic application data
//
// These 12 bytes are research metadata carried INSIDE the MQTT Application
// Message payload. They are NOT MQTT header fields, so this is not a
// deviation from the wire standard — it is the same thing a real industrial
// sensor does when it sends JSON/Protobuf inside its own payload. This
// module has no dependency on Mqtt:: (mqtt-wire.h).
// =============================================================================

std::vector<uint8_t> CreateResearchPayload(uint32_t publisherId,
                                           uint64_t sequence,
                                           uint32_t payloadBytes);

bool ParseResearchPayload(const std::vector<uint8_t>& payload,
                          uint32_t& publisherId,
                          uint64_t& sequence);

#endif // RESEARCH_PAYLOAD_H
