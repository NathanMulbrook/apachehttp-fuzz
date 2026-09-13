#ifndef APACHE_HTTP_FUZZER_H
#define APACHE_HTTP_FUZZER_H

#include <stddef.h>
#include <stdint.h>

#define HTTP_PRELUDE_FLAG 0x01
#define MULTIPACKET_FLAG 0x02
#define WAIT_FOR_RESPONSE_FLAG 0x04
#define MAX_PACKET_COUNT 64

struct fuzzPacketView {
  const uint8_t *data;
  size_t size;
};

struct fuzzInput {
  uint8_t flags;
  size_t packetCount;
  struct fuzzPacketView packets[MAX_PACKET_COUNT];
};

int decodeFuzzInput(const uint8_t *data, size_t size, struct fuzzInput *input);
int fuzzServer(const uint8_t *data, size_t size);
int launchFuzzer(void);

#endif
