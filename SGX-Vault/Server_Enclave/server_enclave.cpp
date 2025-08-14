#include "../common/debug_print.hpp"
#include "client_pubkey.hpp"
#include "server_enclave_t.h"
#include "sgx_error.h"
#include <cstdint>
#include <exception>
#include <map>
#include <sgx_report.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

#define CLIENT_PUBKEY_NUM 2

typedef struct _ra_session_t {
  uint32_t ra_context;
  uint32_t client_id;
  sgx_ec256_public_t g_a;
  sgx_ec256_private_t server_privkey;
  sgx_ec256_public_t g_b;
  uint8_t kdk[16];
  uint8_t vk[16];
  uint8_t sk[16];
  uint8_t mk[16];
} ra_session_t;

/* 全セッションを管理するためのグローバル変数 */
uint32_t g_session_num = 0;
std::vector<ra_session_t> g_ra_sessions;

/* RAセッションを初期化しRAコンテキストを取得 */
sgx_status_t ecall_init_ra(uint32_t client_id, uint32_t *ra_ctx,
                           sgx_ec256_public_t *Ga) {
  /* クライアントIDの境界チェック */
  if (client_id >= CLIENT_PUBKEY_NUM)
    return SGX_ERROR_INVALID_PARAMETER;

  ra_session_t session;
  session.ra_context = g_session_num;
  session.client_id = client_id;
  *ra_ctx = g_session_num;

  g_ra_sessions.emplace_back(session);
  g_session_num++;

  /* セッションキーペアの生成 */
  sgx_status_t status = SGX_SUCCESS;
  sgx_ecc_state_handle_t ecc_state = NULL;

  memset(&g_ra_sessions[*ra_ctx].g_a, 0, sizeof(g_ra_sessions[*ra_ctx].g_a));

  memset(&g_ra_sessions[*ra_ctx].server_privkey, 0,
         sizeof(g_ra_sessions[*ra_ctx].server_privkey));

  try {
    status = sgx_ecc256_open_context(&ecc_state);
    if (status != SGX_SUCCESS)
      throw std::exception();

    status = sgx_ecc256_create_key_pair(&g_ra_sessions[*ra_ctx].server_privkey,
                                        &g_ra_sessions[*ra_ctx].g_a, ecc_state);

    if (status != SGX_SUCCESS)
      throw std::exception();
  } catch (...) {
    if (ecc_state != NULL)
      sgx_ecc256_close_context(ecc_state);

    return status;
  }

  sgx_ecc256_close_context(ecc_state);

  memcpy(Ga, (uint8_t *)&g_ra_sessions[*ra_ctx].g_a,
         sizeof(g_ra_sessions[*ra_ctx].g_a));

  // ocall_print_binary((uint8_t*)&g_ra_sessions[*ra_ctx].g_a,
  //      sizeof(g_ra_sessions[*ra_ctx].g_a));

  return SGX_SUCCESS;
}

/* KDK、VK、SK、MKの生成 */
sgx_status_t derive_shared_keys(uint32_t ra_ctx, sgx_ec256_dh_shared_t dh_key) {
  memset(g_ra_sessions[ra_ctx].kdk, 0, 16);
  memset(g_ra_sessions[ra_ctx].vk, 0, 16);
  memset(g_ra_sessions[ra_ctx].sk, 0, 16);
  memset(g_ra_sessions[ra_ctx].mk, 0, 16);

  sgx_status_t status;
  uint8_t *cmac_key = new uint8_t[16]();

  // KDK
  status = sgx_rijndael128_cmac_msg(
      (sgx_cmac_128bit_key_t *)cmac_key, (uint8_t *)&dh_key,
      SGX_ECP256_KEY_SIZE, (sgx_cmac_128bit_key_t *)g_ra_sessions[ra_ctx].kdk);

  if (status != SGX_SUCCESS)
    return status;

  // VK
  status = sgx_rijndael128_cmac_msg(
      (sgx_cmac_128bit_key_t *)g_ra_sessions[ra_ctx].kdk,
      (uint8_t *)("\x01VK\x00\x80\x00"), 6,
      (sgx_cmac_128bit_key_t *)g_ra_sessions[ra_ctx].vk);

  if (status != SGX_SUCCESS)
    return status;

  // SK
  status = sgx_rijndael128_cmac_msg(
      (sgx_cmac_128bit_key_t *)g_ra_sessions[ra_ctx].kdk,
      (uint8_t *)("\x01SK\x00\x80\x00"), 6,
      (sgx_cmac_128bit_key_t *)g_ra_sessions[ra_ctx].sk);

  if (status != SGX_SUCCESS)
    return status;

  // MK
  status = sgx_rijndael128_cmac_msg(
      (sgx_cmac_128bit_key_t *)g_ra_sessions[ra_ctx].kdk,
      (uint8_t *)("\x01MK\x00\x80\x00"), 6,
      (sgx_cmac_128bit_key_t *)g_ra_sessions[ra_ctx].mk);

  if (status != SGX_SUCCESS)
    return status;

  delete[] cmac_key;

  return SGX_SUCCESS;
}

/* 交換した公開鍵の署名を検証し共通鍵生成 */
sgx_status_t ecall_process_session_keys(uint32_t ra_ctx, uint32_t client_id,
                                        sgx_ec256_public_t *Gb,
                                        sgx_ec256_signature_t *sigsp) {
  /* 範囲外参照である場合はエラー */
  if (ra_ctx > g_session_num || (ra_ctx + 1) > g_ra_sessions.size())
    return SGX_ERROR_UNEXPECTED;

  /* クライアントIDの境界チェック、先行処理で代入した値との一致チェック */
  if (client_id >= CLIENT_PUBKEY_NUM ||
      client_id != g_ra_sessions[ra_ctx].client_id)
    return SGX_ERROR_INVALID_PARAMETER;

  memcpy(&g_ra_sessions[ra_ctx].g_b, Gb, 64);

  /* 公開鍵の連結を生成 */
  sgx_ec256_public_t gb_ga[2];
  memset(&gb_ga[0], 0, sizeof(gb_ga));
  memcpy(&gb_ga[0], &g_ra_sessions[ra_ctx].g_b, 64);
  memcpy(&gb_ga[1], &g_ra_sessions[ra_ctx].g_a, 64);

  sgx_ecc_state_handle_t ecc_state = NULL;

  sgx_status_t status = sgx_ecc256_open_context(&ecc_state);
  if (status != SGX_SUCCESS)
    return status;

  sgx_ec256_dh_shared_t dh_key;
  memset(&dh_key, 0, sizeof(dh_key));

  /* 共有秘密の導出 */
  status = sgx_ecc256_compute_shared_dhkey(
      &g_ra_sessions[ra_ctx].server_privkey,
      (sgx_ec256_public_t *)&g_ra_sessions[ra_ctx].g_b, &dh_key, ecc_state);

  if (status != SGX_SUCCESS) {
    sgx_ecc256_close_context(ecc_state);
    return status;
  }

  /* SigSPの検証 */
  uint8_t result;
  status = sgx_ecdsa_verify((uint8_t *)&gb_ga, sizeof(gb_ga),
                            &client_signature_public_key[client_id], sigsp,
                            &result, ecc_state);

  if (status != SGX_SUCCESS) {
    sgx_ecc256_close_context(ecc_state);
    return status;
  }

  if (result != SGX_EC_VALID) {
    sgx_ecc256_close_context(ecc_state);
    return SGX_ERROR_INVALID_SIGNATURE;
  }

  status = derive_shared_keys(ra_ctx, dh_key);
  if (status != SGX_SUCCESS)
    return status;

  sgx_ecc256_close_context(ecc_state);

  return SGX_SUCCESS;
}

/* QE3とのLocal Attestationに使用するREPORT構造体を生成 */
sgx_status_t ecall_create_report(uint32_t ra_ctx,
                                 sgx_target_info_t *qe3_target_info,
                                 sgx_report_t *report) {
  // 鍵交換実装時はここに両者の公開鍵の連結に対するハッシュ値を同梱する
  sgx_report_data_t report_data = {0};

  // ここでは例として32バイトの0の羅列を対象とする
  uint8_t *original_data = new uint8_t[144]();
  uint8_t *data_hash = new uint8_t[32]();

  memcpy(original_data, &g_ra_sessions[ra_ctx].g_a, 64);
  memcpy(&original_data[64], &g_ra_sessions[ra_ctx].g_b, 64);
  memcpy(&original_data[128], g_ra_sessions[ra_ctx].vk, 16);

  sgx_status_t status =
      sgx_sha256_msg(original_data, 144, (sgx_sha256_hash_t *)data_hash);

  if (status != SGX_SUCCESS)
    return status;

  memcpy(&report_data, data_hash, 32);

  status = sgx_create_report(qe3_target_info, &report_data, report);

  delete[] original_data;
  delete[] data_hash;

  return status;
}

/* 指定したRAセッションを破棄する */
sgx_status_t ecall_destroy_ra_session(uint32_t ra_ctx) {
  /* 範囲外参照である場合はエラー */
  if (ra_ctx > g_session_num || (ra_ctx + 1) > g_ra_sessions.size())
    return SGX_ERROR_UNEXPECTED;

  g_ra_sessions[ra_ctx].ra_context = -1;
  memset(&g_ra_sessions[ra_ctx].g_a, 0, sizeof(sgx_ec256_public_t));
  memset(&g_ra_sessions[ra_ctx].g_b, 0, sizeof(sgx_ec256_public_t));
  memset(&g_ra_sessions[ra_ctx].server_privkey, 0, sizeof(sgx_ec256_private_t));
  memset(&g_ra_sessions[ra_ctx].kdk, 0, 16);
  memset(&g_ra_sessions[ra_ctx].vk, 0, 16);
  memset(&g_ra_sessions[ra_ctx].sk, 0, 16);
  memset(&g_ra_sessions[ra_ctx].mk, 0, 16);

  return SGX_SUCCESS;
}

sgx_status_t ecall_sample_addition(uint32_t ra_ctx, uint8_t *cipher1,
                                   size_t cipher1_len, uint8_t *cipher2,
                                   size_t cipher2_len, uint8_t *iv,
                                   uint8_t *tag1, uint8_t *tag2,
                                   uint8_t *result, size_t *result_len,
                                   uint8_t *iv_result, uint8_t *tag_result) {
  sgx_status_t status = SGX_SUCCESS;
  sgx_ra_key_128_t sk_key, mk_key;

  memcpy(&sk_key, g_ra_sessions[ra_ctx].sk, 16);
  memcpy(&mk_key, g_ra_sessions[ra_ctx].mk, 16);

  if (cipher1_len > 32 || cipher2_len > 32) {
    const char *message = "The cipher size is too large.";
    ocall_print(message, 2);
    status = SGX_ERROR_INVALID_PARAMETER;
    return status;
  }

  /* GCMでは暗号文と平文の長さが同一 */
  uint8_t *plain_1 = new uint8_t[cipher1_len]();
  uint8_t *plain_2 = new uint8_t[cipher2_len]();

  /* GCM復号 */
  status =
      sgx_rijndael128GCM_decrypt(&sk_key, cipher1, cipher1_len, plain_1, iv, 12,
                                 NULL, 0, (sgx_aes_gcm_128bit_tag_t *)tag1);

  if (status != SGX_SUCCESS) {
    const char *message = "Failed to decrypt cipher1.";
    ocall_print(message, 2); // 2はエラーログである事を表す
    ocall_print_status(status);
    return status;
  }

  status =
      sgx_rijndael128GCM_decrypt(&sk_key, cipher2, cipher2_len, plain_2, iv, 12,
                                 NULL, 0, (sgx_aes_gcm_128bit_tag_t *)tag2);

  if (status != SGX_SUCCESS) {
    const char *message = "Failed to decrypt cipher2.";
    ocall_print(message, 2); // 2はエラーログである事を表す
    ocall_print_status(status);
    return status;
  }

  uint64_t num1 = atol((const char *)plain_1);
  uint64_t num2 = atol((const char *)plain_2);

  /* 加算を実行 */
  uint64_t total = num1 + num2;

  /* 返信用に暗号化を実施 */
  std::string total_str = std::to_string(total);
  uint8_t *total_u8 = (uint8_t *)total_str.c_str();

  *result_len = total_str.length();

  /* "32"はEnclave外で決め打ちで確保しているバッファ数 */
  if (*result_len > 32) {
    const char *message = "The result cipher size is too large.";
    ocall_print(message, 2);
    status = SGX_ERROR_INVALID_PARAMETER;
    return status;
  }

  /* RDRANDで真性乱数的にIVを生成 */
  status = sgx_read_rand(iv_result, 12);

  if (status != SGX_SUCCESS) {
    const char *message = "Failed to generate IV inside enclave.";
    ocall_print(message, 2); // 2はエラーログである事を表す
    ocall_print_status(status);
    return status;
  }

  /* 計算結果をGCMで暗号化 */
  status = sgx_rijndael128GCM_encrypt(&mk_key, total_u8, *result_len, result,
                                      iv_result, 12, NULL, 0,
                                      (sgx_aes_gcm_128bit_tag_t *)tag_result);

  if (status != SGX_SUCCESS) {
    const char *message = "Failed to encrypt result.";
    ocall_print(message, 2); // 2はエラーログである事を表す
    ocall_print_status(status);
    return status;
  }

  delete plain_1;
  delete plain_2;

  return status;
}

/* user defined */
#define MRENCLAVE 0
#define MRSIGNER 1

int calc_sealed_len(int message_len) {
  return sgx_calc_sealed_data_size(0, message_len);
}

void do_sealing(uint8_t *message, int message_len, uint8_t *sealed,
                int sealed_len, int policy) {
  uint16_t key_policy;
  sgx_status_t status;
  sgx_attributes_t attr;
  sgx_misc_select_t misc = 0xF0000000;

  attr.flags = 0xFF0000000000000B;
  attr.xfrm = 0;

  if (policy == MRENCLAVE) {
    key_policy = 0x0001;
  } else {
    key_policy = 0x0002;
  }

  status = sgx_seal_data_ex(key_policy, attr, misc, 0, NULL, message_len,
                            message, sealed_len, (sgx_sealed_data_t *)sealed);
  // ocall_print_status(status);
}

int calc_unsealed_len(uint8_t *sealed, int sealed_len) {
  return sgx_get_encrypt_txt_len((sgx_sealed_data_t *)sealed);
}

void do_unsealing(uint8_t *sealed, int sealed_len, uint8_t *unsealed,
                  int unsealed_len, int *error_flag) {
  sgx_status_t status;

  status = sgx_unseal_data((sgx_sealed_data_t *)sealed, NULL, 0, unsealed,
                           (uint32_t *)&unsealed_len);

  // ocall_print_status(status);

  if (status != SGX_SUCCESS) {
    *error_flag = 0xDEADBEEF;
  }
}

int unsealing_and_compare(uint8_t *sealed, int sealed_len, uint8_t *unsealed,
                          int unsealed_len, uint8_t *message, int message_len,
                          int *error_flag) {
  do_unsealing(sealed, sealed_len, unsealed, unsealed_len, error_flag);

  if (unsealed_len != message_len) {
    return -1;
  }

  for (int i = 0; i < unsealed_len; i++) {
    if (unsealed[i] != message[i]) {
      return -1;
    }
  }

  return 0;
}

/*
 * @brief std::mapのキーと値をナル文字で区切りつつ結合する
 * @param[in] data_map 結合するマップ
 * @return
 * 結合されたデータとサイズを格納したpair。メモリは呼び出し元が解放する必要がある。
 */
std::pair<uint8_t *, size_t>
concatenate_map_with_null(const std::map<std::string, std::string> &data_map) {
  size_t total_size = 0;
  for (const auto &pair : data_map) {
    // キーのサイズ + 値のサイズ
    // ※map内のstringがナル終端文字を含んでいる前提
    total_size += pair.first.size();
    total_size += pair.second.size();
  }

  uint8_t *concatenated_data = new (std::nothrow) uint8_t[total_size];
  if (concatenated_data == nullptr) {
    return {nullptr, 0};
  }

  uint8_t *current_ptr = concatenated_data;

  for (const auto &pair : data_map) {
    // キーをコピー (ナル文字も含む)
    memcpy(current_ptr, pair.first.data(), pair.first.size());
    current_ptr += pair.first.size();

    // 値をコピー (ナル文字も含む)
    memcpy(current_ptr, pair.second.data(), pair.second.size());
    current_ptr += pair.second.size();
  }

  return {concatenated_data, total_size};
}

sgx_status_t
register_password_for_sealed_file(uint8_t *sealed_data, int sealed_data_len,
                                  uint8_t *username, int username_len,
                                  uint8_t *password, int password_len) {

  std::map<std::string, std::string> result_map;

  /* ファイルに何も書かれていない場合はunsealingできないので登録のみ */
  if (sealed_data_len == 0 || sealed_data == NULL) {
    result_map = {};

  } else {
    int unsealed_len = calc_unsealed_len(sealed_data, sealed_data_len);
    uint8_t *unsealed = new uint8_t[unsealed_len];
    int error_flag = 0;
    do_unsealing(sealed_data, sealed_data_len, unsealed, unsealed_len,
                 &error_flag);

    // unsealedデータのメモリを解放する前にマップを構築
    size_t current_pos = 0;
    while (current_pos < unsealed_len) {
      const char *key_start =
          reinterpret_cast<const char *>(unsealed + current_pos);

      // キーのナル文字を検索し、その位置から長さを計算
      const char *key_null = static_cast<const char *>(
          memchr(key_start, '\0', unsealed_len - current_pos));
      if (!key_null)
        break; // ナル文字が見つからない場合はデータ破損とみなし終了

      size_t key_len = (key_null - key_start) + 1; // ナル文字を含めた長さ

      current_pos += key_len;
      if (current_pos >= unsealed_len)
        break; // 値がない場合は終了

      // 値のナル文字を検索し、その位置から長さを計算
      const char *value_start =
          reinterpret_cast<const char *>(unsealed + current_pos);
      const char *value_null = static_cast<const char *>(
          memchr(value_start, '\0', unsealed_len - current_pos));
      if (!value_null)
        break;

      size_t value_len = (value_null - value_start) + 1; // ナル文字を含めた長さ

      // 正しい長さでstd::stringを構築し、マップに追加
      result_map[std::string(key_start, key_len)] =
          std::string(value_start, value_len);

      current_pos += value_len;
    }

    delete[] unsealed; // 修正版ではここでメモリを解放
  }

  std::string username_s(reinterpret_cast<const char *>(username),
                         username_len);
  std::string password_s(reinterpret_cast<const char *>(password),
                         password_len);
  result_map[username_s] = password_s;

  std::pair<uint8_t *, size_t> concatenated_pair =
      concatenate_map_with_null(result_map);
  ocall_write_data_2(concatenated_pair.first, concatenated_pair.second);

  /* sealing */
  int sealed_len = calc_sealed_len(concatenated_pair.second);
  uint8_t *sealed = new uint8_t[sealed_len];
  do_sealing(concatenated_pair.first, concatenated_pair.second, sealed,
             sealed_len, 0x1);
  ocall_write_data(sealed, sealed_len);

  return SGX_SUCCESS;
}

test_struct_t sgx_bleed_demo() {

  // 秘密情報に見立てた"bleeded!"がmalloc()された24バイトの領域に格納される
  uint8_t *secret_area = (uint8_t *)malloc(24);
  char *secret_message = (char *)"bleeded!";
  memset(secret_area, 0, 8);
  memcpy(secret_area + 8, secret_message, 8);
  memset(secret_area + 16, 0, 8);

  // これが無いと最適化で消される?
  ocall_print_binary(secret_area, 24);

  // 一度free()する
  free(secret_area);

  // 同じサイズで再度malloc()することで同じ領域を獲得する("bleeded!"が残っている領域)
  test_struct_t *ts = (test_struct_t *)malloc(sizeof(test_struct_t));
  ts->val1 = 0x64;
  ts->val2 = 0x8;
  ts->val3 = 0x64;

  return *ts;
}

void search_and_show_password_from_sealed_file(uint8_t *sealed_data,
                                               int sealed_data_len,
                                               uint8_t *username,
                                               int username_len) {

  std::map<std::string, std::string> result_map;
  int unsealed_len = calc_unsealed_len(sealed_data, sealed_data_len);
  uint8_t *unsealed = new uint8_t[unsealed_len];
  int error_flag = 0;
  do_unsealing(sealed_data, sealed_data_len, unsealed, unsealed_len,
               &error_flag);

  // unsealedデータのメモリを解放する前にマップを構築
  size_t current_pos = 0;
  while (current_pos < unsealed_len) {
    const char *key_start =
        reinterpret_cast<const char *>(unsealed + current_pos);

    // キーのナル文字を検索し、その位置から長さを計算
    const char *key_null = static_cast<const char *>(
        memchr(key_start, '\0', unsealed_len - current_pos));
    if (!key_null)
      break; // ナル文字が見つからない場合はデータ破損とみなし終了

    size_t key_len = (key_null - key_start) + 1; // ナル文字を含めた長さ

    current_pos += key_len;
    if (current_pos >= unsealed_len)
      break; // 値がない場合は終了

    // 値のナル文字を検索し、その位置から長さを計算
    const char *value_start =
        reinterpret_cast<const char *>(unsealed + current_pos);
    const char *value_null = static_cast<const char *>(
        memchr(value_start, '\0', unsealed_len - current_pos));
    if (!value_null)
      break;

    size_t value_len = (value_null - value_start) + 1; // ナル文字を含めた長さ

    // 正しい長さでstd::stringを構築し、マップに追加
    result_map[std::string(key_start, key_len)] =
        std::string(value_start, value_len);

    current_pos += value_len;
  }
  delete[] unsealed;

  /* 指定されたusername(key)が存在するかどうか */
  std::string username_s(reinterpret_cast<const char *>(username),
                         username_len);
  auto it = result_map.find(username_s);
  if (it != result_map.end()) {
    ocall_print(it->second.c_str(), 1);
  } else {
    ocall_print("password does not exist", 2);
  }
}
