#include "error_print.hpp"
#include "server_enclave_u.h"
#include "sgx_eid.h"
#include "sgx_error.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <sgx_dcap_ql_wrapper.h>
#include <sgx_pce.h>
#include <sgx_quote_3.h>
#include <sgx_tcrypto.h>
#include <sgx_ukey_exchange.h>
#include <sgx_urts.h>
#include <sgx_uswitchless.h>
#include <sstream>
#include <thread>
#include <unistd.h>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../common/base64.hpp"
#include "../common/crypto.hpp"
#include "../common/debug_print.hpp"
#include "../common/hexutil.hpp"
#include "../include/httplib.h"
#include "../include/ini.h"
#include "../include/json.hpp"

using namespace httplib;

/* プロトタイプ宣言 */
int initialize_enclave(sgx_enclave_id_t &eid);

int initialize_ra(sgx_enclave_id_t eid, std::string request_json,
                  std::string &response_json, std::string &error_message);

int get_quote(sgx_enclave_id_t eid, std::string request_json,
              std::string &response_json, std::string &error_message);

int process_ra_result(sgx_enclave_id_t eid, std::string request_json,
                      std::string &response_json, std::string &error_message);

int sample_addition(sgx_enclave_id_t eid, std::string request_json,
                    std::string &response_json, std::string error_message);

void destruct_ra_context(sgx_enclave_id_t eid, std::string request_json);

/* settingsファイルからロードした値を格納する構造体 */
typedef struct server_settings_struct {
  std::string pce_path;
  std::string qe3_path;
  std::string ide_path;
  std::string qpl_path;
} settings_t;

settings_t g_settings;

void ocall_write_data(uint8_t *data, int data_len) {
  FILE *fp = fopen("sealed_passwords.dat", "wb");
  size_t bytes_written = fwrite(data, 1, data_len, fp);
  fclose(fp);
}

void ocall_write_data_2(uint8_t *data, int data_len) {
  FILE *fp = fopen("dump.dat", "wb");
  size_t bytes_written = fwrite(data, 1, data_len, fp);
  fclose(fp);
}

/* Enclave内の値の出力を行うOCALL（主にデバッグやログ用） */
void ocall_print(const char *str, int log_type) {
  MESSAGE_TYPE type;
  if (log_type == 0)
    type = DEBUG_LOG;
  else if (log_type == 1)
    type = INFO;
  else
    type = ERROR;

  print_debug_message("OCALL output-> ", type);
  print_debug_message(str, type);

  return;
}

/* SGXステータスを識別し具体的な内容表示する */
void ocall_print_status(sgx_status_t st) {
  print_sgx_status(st);
  return;
}

/* バイナリを標準出力する確認用関数 */
void ocall_print_binary(uint8_t *buf, size_t sz) {
  BIO_dump_fp(stdout, (char *)buf, sz);
  return;
}

/* サーバの実行定義。RA含む各処理はここで完結する */
void server_logics(sgx_enclave_id_t eid) {
  Server svr;

  svr.Post("/init-ra", [&](const Request &req, Response &res) {
    std::string response_json, error_message = "";
    std::string request_json = req.body;

    int ret = initialize_ra(eid, request_json, response_json, error_message);

    if (!ret)
      res.status = 200;
    else {
      /* 通信用にBase64化 */
      char *error_message_b64;
      error_message_b64 = base64_encode<char, char>(
          (char *)error_message.c_str(), error_message.length());

      /* レスポンス用jsonを生成 */
      json::JSON json_obj;
      json_obj["error_message"] = std::string(error_message_b64);
      response_json = json_obj.dump();

      res.status = 500;
    }

    /* レスポンスを返信 */
    res.set_content(response_json, "application/json");
  });

  svr.Post("/get-quote", [&](const Request &req, Response &res) {
    std::string request_json = req.body;
    std::string response_json, error_message = "";

    int ret = get_quote(eid, request_json, response_json, error_message);

    print_debug_message("Quote JSON ->", DEBUG_LOG);
    print_debug_message(response_json, DEBUG_LOG);
    print_debug_message("", DEBUG_LOG);

    if (!ret)
      res.status = 200;
    else {
      /* 通信用にBase64化 */
      char *error_message_b64;
      error_message_b64 = base64_encode<char, char>(
          (char *)error_message.c_str(), error_message.length());

      /* レスポンス用jsonを生成 */
      json::JSON json_obj;
      json_obj["error_message"] = std::string(error_message_b64);
      response_json = json_obj.dump();

      res.status = 500;
    }

    /* レスポンスを返信 */
    res.set_content(response_json, "application/json");
  });

  svr.Post("/ra-result", [&](const Request &req, Response &res) {
    std::string request_json = req.body;
    std::string response_json, error_message = "";

    int ret =
        process_ra_result(eid, request_json, response_json, error_message);

    if (!ret)
      res.status = 200;
    else {
      /* 通信用にBase64化 */
      char *error_message_b64;
      error_message_b64 = base64_encode<char, char>(
          (char *)error_message.c_str(), error_message.length());

      /* レスポンス用jsonを生成 */
      json::JSON json_obj;
      json_obj["error_message"] = std::string(error_message_b64);
      response_json = json_obj.dump();

      res.status = 500;
    }

    /* レスポンスを返信 */
    res.set_content(response_json, "application/json");
  });

  /* リモート計算処理テスト（受信した秘密情報のEnclave内での加算） */
  svr.Post("/sample-addition", [&eid](const Request &req, Response &res) {
    std::string request_json = req.body;
    std::string response_json, error_message = "";

    int ret = sample_addition(eid, request_json, response_json, error_message);

    if (!ret)
      res.status = 200;
    else {
      json::JSON res_json_obj;
      char *error_message_b64;

      error_message_b64 = base64_encode<char, char>(
          (char *)error_message.c_str(), error_message.length());

      res_json_obj["error_message"] = std::string(error_message_b64);
      response_json = res_json_obj.dump();

      res.status = 500;
    }

    print_debug_message("send the result response to SP.", INFO);
    print_debug_message("", INFO);

    res.set_content(response_json, "application/json");
  });

  svr.Post("/destruct-ra", [&](const Request &req, Response &res) {
    std::string request_json = req.body;
    std::string response_json, error_message = "";

    destruct_ra_context(eid, request_json);

    res.status = 200;
    json::JSON res_json_obj;
    res_json_obj["message"] = std::string("OK");
    response_json = res_json_obj.dump();

    res.set_content(response_json, "application/json");
  });

  svr.Get("/hi", [](const Request &req, Response &res) {
    res.set_content("Hello World!", "text/plain");
  });

  svr.Get("/stop", [&](const Request &req, Response &res) {
    /* Enclaveの終了 */
    sgx_destroy_enclave(eid);

    svr.stop();
  });

  svr.listen("localhost", 1234);
}

/* Enclaveの初期化 */
int initialize_enclave(sgx_enclave_id_t &eid) {
  /* LEはDeprecatedになったので、起動トークンはダミーで代用する */
  sgx_launch_token_t token = {0};

  /* 起動トークンが更新されているかのフラグ。Deprecated。 */
  int updated = 0;

  /* 署名済みEnclaveイメージファイル名 */
  std::string enclave_image_name = "enclave.signed.so";

  sgx_status_t status;

  sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;
  void *enclave_ex_p[32] = {0};

  enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = &us_config;

  /*
   * Switchless Callが有効化されたEnclaveの作成。
   * NULLの部分はEnclaveの属性（sgx_misc_attribute_t）が入る部分であるが、
   * 不要かつ省略可能なのでNULLで省略している。
   */
  status = sgx_create_enclave_ex(
      enclave_image_name.c_str(), SGX_DEBUG_FLAG, &token, &updated, &eid, NULL,
      SGX_CREATE_ENCLAVE_EX_SWITCHLESS, (const void **)enclave_ex_p);

  if (status != SGX_SUCCESS) {
    /* error_print.cppで定義 */
    print_sgx_status(status);
    return -1;
  }

  return 0;
}

/* sgx_ra_context_t相当のRAセッション識別子の初期化を行う */
int initialize_ra(sgx_enclave_id_t eid, std::string request_json,
                  std::string &response_json, std::string &error_message) {
  uint32_t ra_ctx = -1; // EPID-RAのsgx_ra_context_t相当
  sgx_status_t status, retval;

  print_debug_message("", INFO);
  print_debug_message("==============================================", INFO);
  print_debug_message("Initialize RA", INFO);
  print_debug_message("==============================================", INFO);
  print_debug_message("", INFO);

  json::JSON req_json_obj = json::JSON::Load(request_json);
  uint32_t client_id = -1;
  size_t tmpsz;

  /* Client ID（署名検証鍵インデックス）のパース */
  std::string client_id_b64 = std::string(base64_decode<char, char>(
      (char *)req_json_obj["client_id"].ToString().c_str(), tmpsz));

  try {
    client_id = std::stoi(client_id_b64);
  } catch (...) {
    error_message = "Invalid client ID format.";
    print_debug_message(error_message, ERROR);
    print_debug_message("", ERROR);

    return -1;
  }

  /* クライアントに返すセッション公開鍵のガワの準備 */
  sgx_ec256_public_t Ga;

  if (SGX_ECP256_KEY_SIZE != 32) {
    error_message = "Internal key size error.";
    print_debug_message(error_message, ERROR);
    print_debug_message("", ERROR);

    return -1;
  }

  memset(&Ga.gx, 0, SGX_ECP256_KEY_SIZE);
  memset(&Ga.gy, 0, SGX_ECP256_KEY_SIZE);

  status = ecall_init_ra(eid, &retval, client_id, &ra_ctx, &Ga);

  if (status != SGX_SUCCESS) {
    error_message = "Failed to initialize RA.";
    print_sgx_status(status);
    print_debug_message(error_message, ERROR);
    print_debug_message("", ERROR);

    return -1;
  }

  print_debug_binary("Server's session pubkey G_a", (uint8_t *)&Ga, sizeof(Ga),
                     DEBUG_LOG);

  print_debug_binary("x-coordinate of G_a", Ga.gx, 32, DEBUG_LOG);
  print_debug_binary("y-coordinate of G_a", Ga.gy, 32, DEBUG_LOG);

  std::string ra_ctx_str;
  char *ra_ctx_b64;

  ra_ctx_str = std::to_string(ra_ctx);
  ra_ctx_b64 = base64_encode<char, char>((char *)ra_ctx_str.c_str(),
                                         ra_ctx_str.length());

  /* レスポンス用JSONの作成 */
  json::JSON res_json_obj;
  res_json_obj["ra_context"] = std::string(ra_ctx_b64);
  res_json_obj["g_a"]["gx"] =
      std::string((char *)base64_encode<char, uint8_t>(Ga.gx, 32));
  res_json_obj["g_a"]["gy"] =
      std::string((char *)base64_encode<char, uint8_t>(Ga.gy, 32));

  print_debug_message("Base64-encoded x-coordinate of Ga ->", DEBUG_LOG);
  print_debug_message(res_json_obj["g_a"]["gx"].ToString(), DEBUG_LOG);
  print_debug_message("", DEBUG_LOG);

  print_debug_message("Base64-encoded y-coordinate of Ga ->", DEBUG_LOG);
  print_debug_message(res_json_obj["g_a"]["gy"].ToString(), DEBUG_LOG);
  print_debug_message("", DEBUG_LOG);

  response_json = res_json_obj.dump();

  return 0;
}

/* Quoteの素材とする、ServerのEnclaveのReport構造体の取得 */
int get_server_enclave_report(sgx_enclave_id_t eid, uint32_t ra_ctx,
                              sgx_target_info_t qe3_target_info,
                              sgx_report_t &report) {
  sgx_status_t status, retval;

  status = ecall_create_report(eid, &retval, ra_ctx, &qe3_target_info, &report);

  if (status != SGX_SUCCESS) {
    print_sgx_status(status);
    std::string message = "Failed to ecall.";
    print_debug_message(message, ERROR);

    return -1;
  }

  if (retval != SGX_SUCCESS) {
    print_sgx_status(status);
    std::string message = "Failed to create REPORT.";
    print_debug_message(message, ERROR);

    return -1;
  }

  return 0;
}

/* セッションキーの処理をしQuoteを取得 */
int get_quote(sgx_enclave_id_t eid, std::string request_json,
              std::string &response_json, std::string &error_message) {
  print_debug_message("==============================================", INFO);
  print_debug_message("Generate and validate session keys", INFO);
  print_debug_message("==============================================", INFO);
  print_debug_message("", INFO);

  json::JSON req_json_obj = json::JSON::Load(request_json);
  size_t tmpsz;

  std::string ra_ctx_str = std::string(base64_decode<char, char>(
      (char *)req_json_obj["ra_context"].ToString().c_str(), tmpsz));

  uint32_t ra_ctx;

  try {
    ra_ctx = std::stoi(ra_ctx_str);
  } catch (...) {
    print_debug_message("Invalid RA context format.", ERROR);
    return -1;
  }

  std::string client_id_str = std::string(base64_decode<char, char>(
      (char *)req_json_obj["client_id"].ToString().c_str(), tmpsz));

  uint32_t client_id;

  try {
    client_id = std::stoi(client_id_str);
  } catch (...) {
    print_debug_message("Invalid RA context format.", ERROR);
    return -1;
  }

  sgx_ec256_public_t Gb;
  sgx_ec256_signature_t sigsp;

  /* クライアントの公開鍵Gb */
  memcpy(Gb.gx,
         base64_decode<uint8_t, char>(
             (char *)req_json_obj["g_b"]["gx"].ToString().c_str(), tmpsz),
         32);
  memcpy(Gb.gy,
         base64_decode<uint8_t, char>(
             (char *)req_json_obj["g_b"]["gy"].ToString().c_str(), tmpsz),
         32);

  /* Gb_Gaに対するECDSA署名であるSigSP */
  memcpy(sigsp.x,
         base64_decode<uint8_t, char>(
             (char *)req_json_obj["sigsp"]["x"].ToString().c_str(), tmpsz),
         32);
  memcpy(sigsp.y,
         base64_decode<uint8_t, char>(
             (char *)req_json_obj["sigsp"]["y"].ToString().c_str(), tmpsz),
         32);

  sgx_status_t status, retval;

  /* 交換した公開鍵の署名を検証し共通鍵生成 */
  status =
      ecall_process_session_keys(eid, &retval, ra_ctx, client_id, &Gb, &sigsp);

  if (status != SGX_SUCCESS) {
    print_sgx_status(status);
    error_message = "Failed to generate shared keys.";
    print_debug_message(error_message, ERROR);

    return -1;
  }

  if (retval != SGX_SUCCESS) {
    print_sgx_status(retval);
    error_message = "Failed to generate shared keys.";
    print_debug_message(error_message, ERROR);

    return -1;
  }

  print_debug_message("==============================================", INFO);
  print_debug_message("Get Quote", INFO);
  print_debug_message("==============================================", INFO);
  print_debug_message("", INFO);

  sgx_target_info_t qe3_target_info;
  quote3_error_t qe3_error;

  /* RAの一環であるQE3とのLAのため、QE3のTarget Infoを取得する */
  qe3_error = sgx_qe_get_target_info(&qe3_target_info);
  ;

  if (qe3_error != SGX_QL_SUCCESS) {
    print_ql_status(qe3_error);
    error_message = "Failed to get QE3's target info.";
    print_debug_message(error_message, ERROR);

    return -1;
  }

  print_debug_binary("QE3's target info", (uint8_t *)&qe3_target_info,
                     sizeof(sgx_target_info_t), DEBUG_LOG);

  /* ServerのEnclaveのREPORT構造体を取得 */
  sgx_report_t report = {0};
  memset(&report, 0, sizeof(sgx_report_t));

  int ret = get_server_enclave_report(eid, ra_ctx, qe3_target_info, report);

  if (ret)
    return -1;

  print_debug_binary("Server Enclave's Report", (uint8_t *)&report,
                     sizeof(sgx_report_t), DEBUG_LOG);

  /* 取得するQuoteのサイズを算出し、そのサイズ数を取得する */
  uint32_t quote_size = 0;
  qe3_error = sgx_qe_get_quote_size(&quote_size);

  if (qe3_error != SGX_QL_SUCCESS) {
    print_ql_status(qe3_error);
    std::string message = "Failed to get Quote size.";
    print_debug_message(message, ERROR);
    print_debug_message("", ERROR);

    return -1;
  }

  print_debug_message("Quote size ->", DEBUG_LOG);
  print_debug_message(std::to_string(quote_size), DEBUG_LOG);
  print_debug_message("", DEBUG_LOG);

  /* Quoteを取得する */
  uint8_t *quote_u8 = new uint8_t[quote_size]();

  qe3_error = sgx_qe_get_quote(&report, quote_size, quote_u8);

  if (qe3_error != SGX_QL_SUCCESS) {
    print_ql_status(qe3_error);
    std::string message = "Failed to get Quote.";
    print_debug_message(message, ERROR);
    print_debug_message("", ERROR);

    return -1;
  }

  print_debug_binary("Server Enclave's Quote", quote_u8, quote_size, DEBUG_LOG);

  /* 値のチェック */
  sgx_quote3_t *quote = (sgx_quote3_t *)quote_u8;
  sgx_ql_auth_data_t *auth_data = NULL;
  sgx_ql_ecdsa_sig_data_t *sig_data = NULL;
  sgx_ql_certification_data_t *cert_data = NULL;

  sig_data = (sgx_ql_ecdsa_sig_data_t *)quote->signature_data;
  auth_data = (sgx_ql_auth_data_t *)sig_data->auth_certification_data;
  cert_data =
      (sgx_ql_certification_data_t *)((uint8_t *)auth_data +
                                      sizeof(*auth_data) + auth_data->size);

  print_debug_message("cert key type ->", DEBUG_LOG);
  print_debug_message(std::to_string(cert_data->cert_key_type), DEBUG_LOG);
  print_debug_message("", DEBUG_LOG);

  /* Report Dataの上位32bitには、完全性を維持したいデータのハッシュが入っている
   */
  print_debug_binary("first 32 bytes of report data",
                     quote->report_body.report_data.d, 32, DEBUG_LOG);

  // ダミー変数。この部分はクライアント側で置換する
  int content_size = 32;
  uint8_t *report_data_content = new uint8_t[content_size]();

  /* レスポンスの生成 */
  std::string quote_b64 =
      std::string(base64url_encode<char, uint8_t>(quote_u8, quote_size));
  std::string report_data_b64 = std::string(
      base64url_encode<char, uint8_t>(report_data_content, content_size));

  /* MAAがURLセーフBase64を受理しているため、その変換を行う */
  print_debug_message("URL-safe-Base64 encoded quote ->", DEBUG_LOG);
  print_debug_message(quote_b64, DEBUG_LOG);
  print_debug_message("", DEBUG_LOG);

  /* Report Dataの上位32ビット（つまりコンテンツのハッシュ値）を渡すのではなく、
   * ハッシュ値に対応する元データの方を渡す点に注意 */
  print_debug_message("URL-safe-Base64 encoded report data content ->",
                      DEBUG_LOG);
  print_debug_message(report_data_b64, DEBUG_LOG);
  print_debug_message("", DEBUG_LOG);

  json::JSON res_json_obj;

  res_json_obj["quote"] = quote_b64;
  res_json_obj["runtimeData"]["data"] = report_data_b64;
  res_json_obj["runtimeData"]["dataType"] = "Binary";
  response_json = res_json_obj.dump();

  memset(quote_u8, 0, quote_size);
  delete[] quote_u8;

  return 0;
}

/* RA結果の処理 */
int process_ra_result(sgx_enclave_id_t eid, std::string request_json,
                      std::string &response_json, std::string &error_message) {
  print_debug_message("==============================================", INFO);
  print_debug_message("Process RA result", INFO);
  print_debug_message("==============================================", INFO);
  print_debug_message("", INFO);

  json::JSON res_json_obj;
  json::JSON req_json_obj = json::JSON::Load(request_json);

  uint32_t ra_ctx = -1;
  size_t tmp;

  ra_ctx = std::stoi(std::string(base64_decode<char, char>(
      (char *)req_json_obj["ra_context"].ToString().c_str(), tmp)));

  if (req_json_obj["ra_result"].ToString() == "true") {
    print_debug_message("RA has been accepted by client.", INFO);
    print_debug_message("", INFO);
  } else if (req_json_obj["ra_result"].ToString() == "false") {
    print_debug_message("RA has been rejected by client.", INFO);
    print_debug_message("", INFO);

    sgx_status_t status, retval;
    status = ecall_destroy_ra_session(eid, &retval, ra_ctx);
  } else {
    std::string error_message = "Invalid RA result format.";
    print_debug_message(error_message, ERROR);
    print_debug_message("", ERROR);

    res_json_obj["error_message"] = error_message;
    response_json = res_json_obj.dump();

    return -1;
  }

  res_json_obj["msg"] = "ok";
  response_json = res_json_obj.dump();

  return 0;
}

/* SPから受信した2値をEnclave内で復号し加算して結果を返却 */
int sample_addition(sgx_enclave_id_t eid, std::string request_json,
                    std::string &response_json, std::string error_message) {
  print_debug_message("==============================================", INFO);
  print_debug_message("Sample Addition", INFO);
  print_debug_message("==============================================", INFO);
  print_debug_message("", INFO);

  json::JSON req_json_obj = json::JSON::Load(request_json);

  uint8_t *cipher1, *cipher2;
  uint8_t *iv, *tag1, *tag2;
  size_t cipher1_len, cipher2_len, tmpsz;
  uint32_t ra_ctx;

  ra_ctx = std::stoi(base64_decode<char, char>(
      (char *)req_json_obj["ra_context"].ToString().c_str(), tmpsz));

  cipher1 = base64_decode<uint8_t, char>(
      (char *)req_json_obj["cipher1"].ToString().c_str(), cipher1_len);

  cipher2 = base64_decode<uint8_t, char>(
      (char *)req_json_obj["cipher2"].ToString().c_str(), cipher2_len);

  iv = base64_decode<uint8_t, char>(
      (char *)req_json_obj["iv"].ToString().c_str(), tmpsz);

  tag1 = base64_decode<uint8_t, char>(
      (char *)req_json_obj["tag1"].ToString().c_str(), tmpsz);

  tag2 = base64_decode<uint8_t, char>(
      (char *)req_json_obj["tag2"].ToString().c_str(), tmpsz);

  sgx_status_t status, retval;
  uint8_t *result, *iv_result, *tag_result;
  size_t result_len;

  iv_result = new uint8_t[12]();
  tag_result = new uint8_t[16]();

  /* 結果用バッファサイズは決め打ち。uint64_t同士の加算であるため、
   * 本来は10バイトもあれば十分である。
   * 行儀よくやるのであれば、サイズ把握用の関数を用意するのが良いが、
   * 事実上二重処理になるため、行う処理の重さと相談する */
  result = new uint8_t[32]();

  /* ECALLを行い秘密計算による加算を実行 */
  print_debug_message("Invoke ECALL for addition.", DEBUG_LOG);
  print_debug_message("", DEBUG_LOG);

  status = ecall_sample_addition(eid, &retval, ra_ctx, cipher1, cipher1_len,
                                 cipher2, cipher2_len, iv, tag1, tag2, result,
                                 &result_len, iv_result, tag_result);

  if (status != SGX_SUCCESS) {
    error_message = "Failed to complete sample addition ECALL.";
    return -1;
  }

  json::JSON res_json_obj;

  res_json_obj["cipher"] =
      std::string(base64_encode<char, uint8_t>(result, result_len));

  res_json_obj["iv"] = std::string(base64_encode<char, uint8_t>(iv_result, 12));

  res_json_obj["tag"] =
      std::string(base64_encode<char, uint8_t>(tag_result, 16));

  response_json = res_json_obj.dump();

  return 0;
}

/* クライアントから受信したRAコンテキストのRAを破棄 */
void destruct_ra_context(sgx_enclave_id_t eid, std::string request_json) {
  print_debug_message("==============================================", INFO);
  print_debug_message("Destruct RA", INFO);
  print_debug_message("==============================================", INFO);
  print_debug_message("", INFO);

  json::JSON req_json_obj = json::JSON::Load(request_json);
  size_t tmpsz;

  std::string ra_ctx_str = std::string(base64_decode<char, char>(
      (char *)req_json_obj["ra_context"].ToString().c_str(), tmpsz));

  uint32_t ra_ctx;
  sgx_status_t retval;

  try {
    ra_ctx = std::stoi(ra_ctx_str);
  } catch (...) {
    print_debug_message("Invalid RA context format.", ERROR);
    return;
  }

  ecall_destroy_ra_session(eid, &retval, ra_ctx);

  print_debug_message("Destructed following RA context -> ", INFO);
  print_debug_message(ra_ctx_str, INFO);
  print_debug_message("", INFO);

  return;
}

#define MRENCLAVE 0
#define MRSIGNER 1

int verify_master_password(sgx_enclave_id_t eid) {
  uint8_t *message;
  uint8_t *sealed;
  uint8_t *unsealed;
  int policy = MRSIGNER;
  int mode;
  sgx_status_t status = SGX_ERROR_UNEXPECTED;
  int sealed_len;
  int message_len;
  std::string master_password;

  print_debug_message("SGX-Vault started", INFO);
  /*
   * Master Password の記録、あるいは照会
   * これで処理が進むか否かが決定する
   */
  const char *file = "master_password.dat";

  /* master_password.datを検索 */
  FILE *fp = fopen(file, "r+");
  if (fp == NULL) {
    print_debug_message("Master passworld file does not found", INFO);

    /* なければファイルを作成 */
    fp = fopen(file, "w+");
    if (fp == NULL) {
      print_debug_message("Failed to create Master password file", ERROR);
      return -1;

    } else {
      print_debug_message("Master password file created", INFO);
    }

    /* ここでmaster passwordを入力させる */
    print_debug_message("Register your master password", INFO);
    std::cout << "> ";
    std::getline(std::cin, master_password);
    print_debug_message("Your master password: " + master_password, INFO);

    message = (uint8_t *)master_password.c_str();
    message_len = strlen((char *)message);

    /* calculete sealed length by ECALL*/
    status = calc_sealed_len(eid, &sealed_len, message_len);
    if (status != SGX_SUCCESS) {
      print_debug_message("Failed to execute calc_sealed_len()", ERROR);
      return -1;
    }
    sealed = new uint8_t[sealed_len];

    /* Execute sealing */
    print_debug_message("Executing sealing", INFO);
    status = do_sealing(eid, message, message_len, sealed, sealed_len, policy);
    if (status != SGX_SUCCESS) {
      print_debug_message("Failed to execute do_sealing()", ERROR);
      return -1;
    }

    std::ofstream ofs(file, std::ios::binary);
    if (!ofs) {
      print_debug_message("Failed to open master password file", ERROR);
      return -1;
    }

    /* Write sealed data to sealed.dat */
    ofs.write((const char *)sealed, sealed_len);
    print_debug_message(
        "Output sealed data to master password file successfully", INFO);

  } else {
    /* ファイルが有る場合はマスターパスワードを入力させて、sealedされたデータと比較する
     */
    print_debug_message("Found sealed master password file", INFO);

    print_debug_message("Input your Master password", INFO);
    std::cout << "> ";
    std::getline(std::cin, master_password);

    /* sealed.datを読み取り専用でオープン */
    std::ifstream ifs(file, std::ios::binary);
    if (!ifs) {
      print_debug_message("Failed to open master password file", ERROR);
      return -1;
    }

    ifs.seekg(0, std::ios::end);
    sealed_len = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    sealed = new uint8_t[sealed_len];

    ifs.read((char *)sealed, sealed_len);

    int unsealed_len;
    status = calc_unsealed_len(eid, &unsealed_len, sealed, sealed_len);
    if (status != SGX_SUCCESS) {
      print_debug_message("Failed to execute calc_unsealed_len()", ERROR);
      return -1;
    }

    unsealed = new uint8_t[unsealed_len];

    /* Execute unsealing and compare input vs sealed master password*/
    int error_flag = 0;
    int retval = 0;
    message = (uint8_t *)master_password.c_str();
    message_len = strlen((char *)message);
    status =
        unsealing_and_compare(eid, &retval, sealed, sealed_len, unsealed,
                              unsealed_len, message, message_len, &error_flag);
    if (error_flag != 0) {
      print_debug_message("Failed to unsealing", ERROR);
      return -1;
    }

    if (retval != 0) {
      print_debug_message("Invalid Master password", ERROR);
      return -1;
    }

    print_debug_message("Your Input: " + master_password, INFO);
    std::string unsealed_s((char *)unsealed, unsealed_len);
    print_debug_message("Unsealed Master password: " + unsealed_s, INFO);
  }

  return 0;
}

int register_password(sgx_enclave_id_t eid) {
  std::string username;
  std::string password;
  std::map<std::string, std::string> password_map;
  std::string filepath = "sealed_passwords.dat";

  /* sealed_passwords.datを開く */
  FILE *fp = fopen(filepath.c_str(), "r+");

  /* 存在しなければ作成し、読み書きで開く */
  if (fp == NULL) {
    print_debug_message(filepath + " does not found", INFO);
    print_debug_message("Creating " + filepath, INFO);
    fp = fopen(filepath.c_str(), "w+");
  } else {
    print_debug_message(filepath + "found", INFO);
  }

  /* ファイルの内容をすべて取り出す */
  fseek(fp, 0, SEEK_END);
  size_t file_size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  std::vector<uint8_t> buffer(file_size);

  size_t bytes_read = fread(buffer.data(), 1, file_size, fp);
  if (bytes_read != file_size) {
    fclose(fp);
    return -1;
  }

  print_debug_message("Enter username", INFO);
  std::cout << "> ";
  std::cin >> username;

  print_debug_message("Enter password", INFO);
  std::cout << "> ";
  std::cin >> password;

  /*
   * ここで、抜き出したsealedデータとk,vをecallで送りつける
   */
  sgx_status_t retval = SGX_ERROR_UNEXPECTED;
  sgx_status_t status = register_password_for_sealed_file(
      eid, &retval, (uint8_t *)&buffer[0], buffer.size(),
      (uint8_t *)username.c_str(), username.length() + 1,
      (uint8_t *)password.c_str(), password.length() + 1);

  print_sgx_status(retval);
  print_sgx_status(status);

  if (retval != SGX_SUCCESS || status != SGX_SUCCESS) {
    print_debug_message("Failed to execute register_password_for_sealed_file()", ERROR);
    fclose(fp);
    return -1;
  }

  print_debug_message("Password stored successfully", INFO);
  fclose(fp);
  return 0;
}


int search_and_show_password(sgx_enclave_id_t eid) {
  std::string filepath = "sealed_passwords.dat";
  FILE *fp = fopen(filepath.c_str(), "r");

  if (fp == NULL) {
    print_debug_message(filepath+" does not found", ERROR);
    return -1;
  }

  /* ファイルの内容をすべて取り出す */
  fseek(fp, 0, SEEK_END);
  size_t file_size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  std::vector<uint8_t> buffer(file_size);

  size_t bytes_read = fread(buffer.data(), 1, file_size, fp);
  if (bytes_read != file_size) {
    fclose(fp);
    return -1;
  }

  print_debug_message("Enter username", INFO);
  std::string username;
  std::cout << "> ";
  std::cin >> username;

  sgx_status_t retval = SGX_ERROR_UNEXPECTED;
  sgx_status_t status = search_and_show_password_from_sealed_file(eid, (uint8_t *)&buffer[0], buffer.size(), (uint8_t*)username.c_str(), username.length()+1);

  return 0;
}

void smashing_sgx(sgx_enclave_id_t eid) {

  print_debug_message("Executing sgx_bleed_demo()", INFO);
  test_struct_t ts;
  sgx_status_t status = sgx_bleed_demo(eid, &ts);
  uint64_t *ptr = (uint64_t *)&ts;
  size_t size = sizeof(ts) / 8;
  print_debug_message("Display structure values", INFO);
  for (size_t i = 0; i < size; i++) {
    printf("0x%016lx\n", ptr[i]);
  }
}

int SGX_Vault(sgx_enclave_id_t eid) {
  if (verify_master_password(eid) != 0) {
    print_debug_message("Failed to execute verify_master_password()", ERROR);
    return -1;
  }

  std::string userinput = "0";
  print_debug_message("Select your option", INFO);
  while (userinput != "4") {
    std::cout << "0 Smashing SGX !!!" << std::endl;
    std::cout << "1 Register your new password" << std::endl;
    std::cout << "2 Search and show your password" << std::endl;
    std::cout << "3 Select and delete your password" << std::endl;
    std::cout << "4 exit SGX-Vault" << std::endl;
    std::cout << "> ";
    std::cin >> userinput;

    switch (stoi(userinput)) {
    case 0:
      smashing_sgx(eid);
      userinput = "4";
      break;
    case 1:
      register_password(eid);
      break;
    case 2:
      search_and_show_password(eid);
      break;
    case 4:
      std::cout << "Bye." << std::endl;
      break;
    default:
      print_debug_message("Invalid option", INFO);
      break;
    }
  }

  return 0;
}

int main() {
  print_debug_message("", INFO);
  print_debug_message("Launched ISV's untrusted application.", INFO);

  /* Azure上でのDCAP-RAでは、プロセス外で動作するAEを使用するout-of-procモードが
   * 推奨されているため、out-of-procモードを前提とする */
  bool is_out_of_proc = false;
  char *out_of_proc = std::getenv("SGX_AESM_ADDR");

  if (!out_of_proc) {
    std::string message = "Only out-of-proc mode is supported. ";
    message += "Check your machine's configuration.";
    print_debug_message(message, ERROR);

    return -1;
  }

  sgx_enclave_id_t eid = -1;

  /* Enclaveの初期化 */
  if (initialize_enclave(eid) < 0) {
    std::string message = "Failed to initialize Enclave.";
    print_debug_message(message, ERROR);

    return -1;
  }

  /* サーバの起動（RAの実行） */
  // std::thread srvthread(server_logics, eid);

  /* サーバ停止準備。実際の停止処理は後ほど実装 */
  // srvthread.join();

  if (SGX_Vault(eid) != 0) {
    print_debug_message("Error occured while SGX-Vault was running", ERROR);
    return -1;
  }

  sgx_destroy_enclave(eid);
}

/*
 * マスターパスワードのシーリングデータをチェック
 * なければ入力して登録させる
 * あれば入力を促してチェック
 * */
