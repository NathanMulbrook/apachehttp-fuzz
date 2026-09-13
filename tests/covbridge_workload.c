#include <stddef.h>
#include <stdint.h>

static volatile uint64_t sink;

void covbridgeTestWorkload(const uint8_t *data, size_t size) {
  size_t index;

  if (size > 0 && data[0] == 'A') {
    sink += 3;
  }
  if (size > 2 && data[1] == 'B' && data[2] == 'C') {
    sink += 7;
  }
  for (index = 0; index < size; index++) {
    sink += data[index] & 1;
  }
}
