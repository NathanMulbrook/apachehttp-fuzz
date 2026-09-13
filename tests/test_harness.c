#include "../fuzzer.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void testRaw(void) {
  const uint8_t value[] = {HTTP_PRELUDE_FLAG, 'G', 'E', 'T'};
  struct fuzzInput input;

  assert(decodeFuzzInput(value, sizeof(value), &input) == 0);
  assert(input.flags == HTTP_PRELUDE_FLAG);
  assert(input.packetCount == 1);
  assert(input.packets[0].size == 3);
  assert(memcmp(input.packets[0].data, "GET", 3) == 0);
}

static void testMultipacket(void) {
  const uint8_t value[] = {0x87, 0, 3, 'o', 'n', 'e', 0, 3, 't', 'w', 'o'};
  struct fuzzInput input;

  assert(decodeFuzzInput(value, sizeof(value), &input) == 0);
  assert(input.flags == 0x87);
  assert(input.packetCount == 2);
  assert(input.packets[0].size == 3);
  assert(input.packets[1].size == 3);
  assert(memcmp(input.packets[0].data, "one", 3) == 0);
  assert(memcmp(input.packets[1].data, "two", 3) == 0);
}

static void testMalformed(void) {
  const uint8_t noPackets[] = {MULTIPACKET_FLAG};
  const uint8_t shortLength[] = {MULTIPACKET_FLAG, 0};
  const uint8_t zeroLength[] = {MULTIPACKET_FLAG, 0, 0};
  const uint8_t shortBody[] = {MULTIPACKET_FLAG, 0, 2, 'x'};
  struct fuzzInput input;

  assert(decodeFuzzInput(NULL, 0, &input) == -1);
  assert(decodeFuzzInput(noPackets, sizeof(noPackets), &input) == -1);
  assert(decodeFuzzInput(shortLength, sizeof(shortLength), &input) == -1);
  assert(decodeFuzzInput(zeroLength, sizeof(zeroLength), &input) == -1);
  assert(decodeFuzzInput(shortBody, sizeof(shortBody), &input) == -1);
}

static void testPacketLimit(void) {
  uint8_t value[1 + 65 * 3];
  struct fuzzInput input;
  size_t packet;

  value[0] = MULTIPACKET_FLAG;
  for (packet = 0; packet < 65; packet++) {
    value[1 + packet * 3] = 0;
    value[2 + packet * 3] = 1;
    value[3 + packet * 3] = (uint8_t)packet;
  }
  assert(decodeFuzzInput(value, 1 + 64 * 3, &input) == 0);
  assert(input.packetCount == 64);
  assert(decodeFuzzInput(value, sizeof(value), &input) == -1);
}

int main(void) {
  testRaw();
  testMultipacket();
  testMalformed();
  testPacketLimit();
  puts("PASS harness framing");
  return 0;
}
