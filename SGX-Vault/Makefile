######## SGX SDKに関する設定 ########

# SGXSDKの場所
SGX_SDK ?= /opt/intel/sgxsdk
# 動作モード。ここではHWかSIM。make SGX_MODE=SIMのようにしてオプションで指定可能
SGX_MODE ?= HW
# マシンのアーキテクチャ。32bitか64bit
SGX_ARCH ?= x64
# Enclaveのデバッグモード。1ならDebug版、0なら製品版
SGX_DEBUG ?= 0


## マシンが32bitであればアーキテクチャの変数を更新する
ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif


## アーキテクチャに応じて使用するSGXSDKのツールを設定する
#  32bit版の場合
ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32                         # コンパイル時の共通オプション
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib                # SGX関係のライブラリの場所
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign # SGX署名ツールの場所
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r     # Edger8r Toolの場所
#  64bit版の場合。それぞれの変数の内訳は同上
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif


## DEBUGモードとPRERELEASEモードは同時に有効にできないので弾く
ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif


## DEBUGモード有無に応じてコンパイル共通フラグに追記
ifeq ($(SGX_DEBUG), 1)
		SGX_COMMON_CFLAGS += -O0 -g # 最適化なし、コンパイル時デバック情報表示
else
		SGX_COMMON_CFLAGS += -O2    # 最適化あり
endif



######## クライアント側アプリケーション（Client_App）に関する設定 ########

## コンパイル時に使用するC/C++のソースを列挙
Client_Cpp_Files := Client_App/client_app.cpp common/base64.cpp common/debug_print.cpp common/hexutil.cpp \
				common/crypto.cpp common/jwt_util.cpp

## 使用するincludeファイル（ヘッダ）がある場所を列挙
Client_Include_Paths := -IClient_App -I$(SGX_SDK)/include -Icommon -Iinclude

## Client_Appのコンパイル時に使用するオプションを指定。
Client_C_Flags := $(SGX_COMMON_CFLAGS) $(Client_Include_Paths)

## 実際にはC++コンパイルするので、それ用の最終的なオプションを生成
Client_Cpp_Flags := $(Client_C_Flags) -std=c++11 -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

## リンクオプション
Client_Link_Flags := $(SGX_COMMON_CFLAGS) -lpthread -lcrypto -lssl

## オブジェクトファイルを指定
Client_Cpp_Objects := $(Client_Cpp_Files:.cpp=.o)

## UntrustedのAppの実行バイナリ名を指定
Client_App_Name := client_app


######## SGXサーバ側Enclave外アプリケーション（Server_App）に関する設定 ########

## シミュレーションモードの場合は専用のUntrusted用ライブラリを用いる
ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

## コンパイル時に使用するC/C++のソースを列挙
App_Cpp_Files := Server_App/server_app.cpp Server_App/error_print.cpp common/base64.cpp \
				common/debug_print.cpp common/hexutil.cpp common/crypto.cpp

## 使用するincludeファイル（ヘッダ）がある場所を列挙
App_Include_Paths := -IServer_App -I$(SGX_SDK)/include -Icommon -Iinclude

## Appのコンパイル時に使用するオプションを指定。
#  共通オプション、位置独立コード、不明なスコープ属性への警告を無視、Includeパス
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)


## EnclaveのDEBUGモードに応じてデバッグ可否のフラグをCコンパイルオプションに追加する。
#   Debug - DEBUGフラグを付与（デバッグ可）
#   Prerelease - NDEBUG（NO DEBUGの意）フラグとDEBUGフラグ双方を付与（デバッグ可らしい）
#   Release - NDEBUGフラグを付与（デバッグ不可）
ifeq ($(SGX_DEBUG), 1)
	App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif


## 実際にはC++コンパイルするので、それ用の最終的なオプションを生成
App_Cpp_Flags := $(App_C_Flags) -std=c++11 -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

## リンクオプション
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) \
            		-Wl,--whole-archive -lsgx_uswitchless -Wl,--no-whole-archive \
					-lsgx_ukey_exchange -lsgx_dcap_ql -ldcap_quoteprov -lsgx_tcrypto \
					-l$(Urts_Library_Name) -lpthread -lcrypto -lssl

## シミュレーションモードの場合は専用のライブラリを紐付ける
ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

## オブジェクトファイルを指定
App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

## UntrustedのAppの実行バイナリ名を指定
App_Name := server_app



######## SGXサーバのEnclaveアプリケーションに関する設定 ########
## シミュレーションモードの場合は専用のTrusted用ライブラリを用いる
ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif


## SGX用暗号ライブラリを指定（他にはIntel IPPなどが使えるはず）
Crypto_Library_Name := sgx_tcrypto

## コンパイル時に使用するC/C++のソースを列挙
Enclave_Cpp_Files := Server_Enclave/server_enclave.cpp

## 使用するincludeファイル（ヘッダ）がある場所を列挙
Enclave_Include_Paths := -IServer_Enclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport \
						-I$(SGX_SDK)/include/libcxx -Icommon


## Enclaveのコンパイル時に使用するオプションを指定。
#  共通オプション、通常のincludeファイルを検索しない（SGX専用のを使う）、
#  シンボルの外部隠蔽、位置独立実行形式、スタック保護有効化、使用するIncludeファイルのパス
Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)

## 実際にはC++コンパイルするので、それ用の最終的なオプションを生成
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++

## 多すぎるので詳細はDeveloper Reference参照。Switchless CallのIncludeを忘れない事。
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -lsgx_tswitchless -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0
	# -Wl,--version-script=Enclave/Enclave.lds


## オブジェクトファイルを設定
Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)


## Enclaveイメージ名とEnclave設定ファイル名の設定
Enclave_Name := enclave.so
Signing_Pubkey := Server_Enclave/public_key.pem
Signing_Material := Server_Enclave/enclave_sig.dat
Signature_File := Server_Enclave/signature.dat
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Server_Enclave/Enclave.config.xml


## HWモードかつRELEASEモードの際は専用のフラグを設定
ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


## makeコマンド向け設定
#  make時にallコマンドとrunコマンドに対応（例：make all）
.PHONY: all run

## ややこしいが、Makefileはその場で依存関係が解決できない場合は後続の行を見に行くため、
## allやrunの内容はMakefileのこの行までの記述で実現はできない（Makeが後ろの方を勝手に見てくれる）

## ビルドを実行
all: $(App_Name) $(Signed_Enclave_Name) $(Client_App_Name)

run: all # runはallの結果に依存
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif



######## クライアント側Appオブジェクト関する設定（つまりビルド設定） ########

## Appのオブジェクトファイルを生成。$(CC)は暗黙のルールにより、デフォルトでg++コマンド。
Client_App/%.o: Client_App/%.cpp
	@$(CXX) $(Client_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

## commonフォルダ内のコードについても同様にオブジェクトファイルを生成
common/%.o: common/%.cpp
	@$(CXX) $(Client_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

## リンクによりClient_Appの実行ファイルを生成
$(Client_App_Name): $(Client_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Client_Link_Flags)
	@echo "LINK =>  $@"



######## SGXサーバ側Appオブジェクト関する設定（ビルド設定） ########

## Edger8rによりUntrusted向けエッジ関数のソースを生成
Server_App/server_enclave_u.c: $(SGX_EDGER8R) Server_Enclave/server_enclave.edl
	@cd Server_App && $(SGX_EDGER8R) --untrusted ../Server_Enclave/server_enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

## ソースによりエッジ関数のオブジェクトファイルを生成。$(CC)は暗黙のルールにより、デフォルトでccコマンド。
Server_App/server_enclave_u.o: Server_App/server_enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

## Appのオブジェクトファイルを生成。$(CC)は暗黙のルールにより、デフォルトでg++コマンド。
Server_App/%.o: Server_App/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

## リンクによりAppの実行ファイルを生成
$(App_Name): Server_App/server_enclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


######## Enclaveオブジェクト関する設定（ビルド設定） ########

## Edger8rによりTrusted向けエッジ関数のソースを生成
Server_Enclave/server_enclave_t.c: $(SGX_EDGER8R) Server_Enclave/server_enclave.edl
	@cd Server_Enclave && $(SGX_EDGER8R) --trusted ../Server_Enclave/server_enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

## ソースによりエッジ関数のオブジェクトファイルを生成
Server_Enclave/server_enclave_t.o: Server_Enclave/server_enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

## Enclaveのオブジェクトファイルを生成
Server_Enclave/%.o: Server_Enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

## Enclaveの未署名イメージ（共有ライブラリ）の生成
$(Enclave_Name): Server_Enclave/server_enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

## 秘密鍵からの公開鍵の生成
$(Signing_Pubkey): Server_Enclave/private_key.pem
	@openssl rsa -in Server_Enclave/private_key.pem -pubout -out $@

## 2段階署名のための署名用材料の生成
$(Signing_Material): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) gendata -enclave $(Enclave_Name) -config $(Enclave_Config_File) -out $@

## 2段階署名のための署名ファイルの生成
$(Signature_File): $(Signing_Material)
	@openssl dgst -sha256 -out $@ -sign Server_Enclave/private_key.pem -keyform PEM $(Signing_Material)

## Enclave未署名イメージに対しsgx_signで署名を実施
$(Signed_Enclave_Name): $(Enclave_Name) $(Signing_Material) $(Signature_File) $(Signing_Pubkey)
#	@$(SGX_ENCLAVE_SIGNER) sign -key Server_Enclave/private_key.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@$(SGX_ENCLAVE_SIGNER) catsig -enclave $(Enclave_Name) -config $(Enclave_Config_File) -out $@ -key $(Signing_Pubkey) -sig $(Signature_File) -unsigned $(Signing_Material)
	@echo "SIGN =>  $@"

## クリーンアップ用サブコマンドの定義
.PHONY: clean

clean:
	@rm -f $(App_Name) $(Client_App_Name) $(Enclave_Name) $(Signing_Material) $(Signature_File) $(Signing_Pubkey) $(Signed_Enclave_Name) $(App_Cpp_Objects) $(Client_Cpp_Objects) Server_App/server_enclave_u.* $(Enclave_Cpp_Objects) Server_Enclave/server_enclave_t.*