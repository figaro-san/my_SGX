#include "Enclave_t.h"
#include "sgx_error.h"
#include <sgx_trts.h>
#include <string.h>

test_struct_t sgx_bleed() {
  // 秘密情報に見立てた"bleeded!"がmalloc()された24バイトの領域に格納される
  uint8_t *secret_area = (uint8_t *)malloc(24);
  char *secret_message = (char *)"bleeded!";
  memset(secret_area, 0, 8);
  memcpy(secret_area + 8, secret_message, 8);
  memset(secret_area + 16, 0, 8);

  // これが無いと最適化で消される?
  //ocall_print_binary(secret_area, 24);

  // 一度free()する
  free(secret_area);

  // 同じサイズで再度malloc()することで同じ領域を獲得する("bleeded!"が残っている領域)
  test_struct_t *ts = (test_struct_t *)malloc(sizeof(test_struct_t));
  ts->val1 = 0x64;
  ts->val2 = 0x8;
  ts->val3 = 0x64;

  return *ts;
}

uint8_t ptr1[4096];
uint8_t ptr2[4096];
uint8_t ptr3[4096];
uint8_t ptr4[4096];
uint8_t ptr5[4096];
uint8_t secret;

void init_controlled_channel_attack(uint64_t *address1, uint64_t *address2) {
  memset(ptr1, 0x41, 4096);
  memset(ptr2, 0x42, 4096);
  memset(ptr3, 0x43, 4096);
  memset(ptr4, 0x44, 4096);
  memset(ptr5, 0x45, 4096);

  uint8_t rand;
  sgx_status_t status = sgx_read_rand(&rand, 1);

  if (rand < 128) {
    secret = 0;
  } else {
    secret = 1;
  }

  *address1 = (uint64_t)ptr2;
  *address2 = (uint64_t)ptr4;
}

void controlled_channel_attack() {
  uint8_t value;

  if (secret == 0) {
    value = ptr2[0];

  } else {
    value = ptr4[0];
  }
}
