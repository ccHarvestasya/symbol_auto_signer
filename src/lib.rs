#![deny(clippy::all)]

use std::str::FromStr;

use ed25519_dalek::Keypair;
use hex::FromHex;
use napi::{Error, Status};
use rand::rngs::OsRng;
use tss_esapi::{
  attributes::{NvIndexAttributesBuilder, SessionAttributes},
  constants::SessionType,
  handles::NvIndexTpmHandle,
  interface_types::{
    algorithm::HashingAlgorithm,
    resource_handles::{NvAuth, Provision},
  },
  structures::{MaxNvBuffer, NvPublic, NvPublicBuilder, SymmetricDefinition},
  tcti_ldr::DeviceConfig,
  Context, TctiNameConf,
};

// tpm2_getcap handles-nv-index
// tpm2_nvreadpublic 0x01FFE00A
// tpm2_nvundefine 0x01FFE00A

#[macro_use]
extern crate napi_derive;

// NVインデックスの値
const NV_INDEX_VAL: u32 = 0x01FFE00A;

#[napi]
pub fn sum(a: i32, b: i32) -> i32 {
  a + b
}

#[napi]
pub fn register_private_key(pri_key: Option<String>) -> Result<(), Error> {
  let pk: String;
  if let Some(pkey) = pri_key {
    if pkey.len() != 64 {
      return Err(Error::new(
        Status::InvalidArg,
        "Invalid private key length".to_string(),
      ));
    }
    pk = pkey;
  } else {
    // 引数無しの場合、OsRngを使用してキーペアを生成
    let mut csprng: OsRng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    // 鍵ペアを表示
    println!(
      "PrivateKey: {}",
      hex::encode_upper(keypair.secret.as_bytes())
    );
    println!(
      "PublicKey : {}",
      hex::encode_upper(keypair.public.as_bytes())
    );
    pk = hex::encode_upper(keypair.secret.as_bytes());
  }

  // TPMデバイスを指定
  let tcti_name_conf: TctiNameConf = TctiNameConf::Device(
    DeviceConfig::from_str("/dev/tpmrm0").expect("Failed to create DeviceConfig"),
  );
  // コンテキストを作成
  let mut context: Context = Context::new(tcti_name_conf).expect("Failed to create TPM context");
  // 認証セッションを開始
  start_auth_session(&mut context);

  // NVインデックスを定義
  create_nv_index(&mut context);

  // NVメモリに書き込み
  let pk_bytes = Vec::from_hex(&pk).expect("Failed to convert hex string to bytes");
  write_nv_memory(&mut context, pk_bytes);

  Ok(())
}

#[napi]
pub fn delete_private_key() -> () {
  // TPMデバイスを指定
  let tcti_name_conf: TctiNameConf = TctiNameConf::Device(
    DeviceConfig::from_str("/dev/tpmrm0").expect("Failed to create DeviceConfig"),
  );
  // コンテキストを作成
  let mut context: Context = Context::new(tcti_name_conf).expect("Failed to create TPM context");
  // 認証セッションを開始
  start_auth_session(&mut context);
  // NVインデックスを削除
  delete_nv_index(&mut context);
}

#[napi]
pub fn read_private_key() -> () {
  // TPMデバイスを指定
  let tcti_name_conf: TctiNameConf = TctiNameConf::Device(
    DeviceConfig::from_str("/dev/tpmrm0").expect("Failed to create DeviceConfig"),
  );
  // コンテキストを作成
  let mut context: Context = Context::new(tcti_name_conf).expect("Failed to create TPM context");
  // 認証セッションを開始
  start_auth_session(&mut context);
  // NVメモリから読み取り
  read_nv_memory(&mut context);
}

/**
 * 認証セッションを開始
 */
fn start_auth_session(context: &mut Context) -> () {
  // 認証セッションを開始
  let session = context
    .start_auth_session(
      None,
      None,
      None,
      SessionType::Hmac,
      SymmetricDefinition::AES_128_CFB,
      HashingAlgorithm::Sha256,
    )
    .expect("Failed to start auth session")
    .expect("Received invalid handle");
  let (session_attributes, session_attributes_mask) = SessionAttributes::builder()
    .with_decrypt(true)
    .with_encrypt(true)
    .build();
  context
    .tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    .expect("Failed to set session attributes");
  context.set_sessions((Some(session), None, None));
}

/**
 * NVインデックスを作成
 */
fn create_nv_index(context: &mut Context) -> () {
  // NVインデックスを定義
  let nv_index: NvIndexTpmHandle =
    NvIndexTpmHandle::new(NV_INDEX_VAL).expect("Failed to create NV index");

  // NVインデックス属性を定義
  let nv_index_attr = NvIndexAttributesBuilder::new()
    .with_owner_read(true)
    .with_owner_write(true)
    .build()
    .expect("Failed to build NV index attributes");

  // NV領域を作成
  let nv_public: NvPublic = NvPublicBuilder::new()
    .with_nv_index(nv_index)
    .with_index_name_algorithm(HashingAlgorithm::Sha256)
    .with_index_attributes(nv_index_attr)
    .with_data_area_size(32) // 秘密鍵のサイズ
    .build()
    .expect("Failed to build NV public");

  // NVインデックスを登録
  context
    .nv_define_space(Provision::Owner, None, nv_public)
    .expect("Failed to define NV space");
}

/**
 * NVメモリにデータを書き込む
 */
fn write_nv_memory(context: &mut Context, data: Vec<u8>) -> () {
  // NVインデックスを定義
  let nv_index: NvIndexTpmHandle =
    NvIndexTpmHandle::new(NV_INDEX_VAL).expect("Failed to create NV index");

  // NVインデックスハンドラを定義
  let nv_index_handle = context
    .tr_from_tpm_public(nv_index.into())
    .expect("Failed to convert TPM NV index to ESYS NV index");

  // データをNV領域に書き込み
  let data = MaxNvBuffer::try_from(data).expect("Failed to create NV buffer");

  context
    .nv_write(NvAuth::Owner, nv_index_handle.into(), data, 0)
    .expect("Failed to write to NV memory");

  println!("Secret key has been written to NV memory.");
}

/**
 * NVメモリからデータを読み取る
 */
fn read_nv_memory(context: &mut Context) -> () {
  // NVインデックスを定義
  let nv_index: NvIndexTpmHandle =
    NvIndexTpmHandle::new(NV_INDEX_VAL).expect("Failed to create NV index");

  // NVインデックスハンドラを定義
  let nv_index_handle = context
    .tr_from_tpm_public(nv_index.into())
    .expect("Failed to convert TPM NV index to ESYS NV index");

  // NV領域からデータを読み取り
  let read_buffer = context
    .nv_read(NvAuth::Owner, nv_index_handle.into(), 32, 0)
    .expect("Failed to read from NV memory");

  println!(
    "Read from NV memory: {}",
    hex::encode_upper(read_buffer.as_slice())
  );
}

/**
 * NVインデックスを削除
 */
fn delete_nv_index(context: &mut Context) -> () {
  // NVインデックスを定義
  let nv_index: NvIndexTpmHandle =
    NvIndexTpmHandle::new(NV_INDEX_VAL).expect("Failed to create NV index");

  // NVインデックスハンドラを定義
  let nv_index_handle = context
    .tr_from_tpm_public(nv_index.into())
    .expect("Failed to convert TPM NV index to ESYS NV index");

  // NVインデックスを削除
  context
    .nv_undefine_space(Provision::Owner, nv_index_handle.into())
    .expect("Failed to undefine NV space");

  println!("NV Index has been deleted.");
}
