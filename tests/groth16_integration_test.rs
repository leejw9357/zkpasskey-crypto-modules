use std::path::PathBuf;

use ark_serialize::CanonicalSerialize;
use common::gadget::anchor::AnchorScheme;
use zkpasskey_crypto_modules::{
    interface::{
        anchor::{PoseidonAnchorKeyExtension, SecretDto},
        signature::SchnorrPublicKeyExtension,
        snark::ProvingKeyExtension,
    },
    service::{
        anchor::anchor::build_poseidon_anchor_from_strings,
        constants::{AppCurve, AppField, BN254, Blake2},
        key::io::{load_key_uncompressed, save_key_uncompressed},
        snark::snark::{generate_and_write_proving_key, generate_proof},
    },
};

/// 테스트용 임시 디렉토리 생성
fn setup_test_dir() -> PathBuf {
    let test_dir = PathBuf::from("test_outputs");
    if !test_dir.exists() {
        std::fs::create_dir_all(&test_dir).unwrap();
    }
    test_dir
}

fn setup_test_jwt() -> (String, String, String) {
    let n = "6S7asUuzq5Q_3U9rbs-PkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb_XqZaKgSYaC_h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONYW5Zu3PwyvAWk5D6ueIUhLtYzpcB-etoNdL3Ir2746KIy_VUsDwAM7dhrqSK8U2xFCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAKctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcajtw".to_string();
    let e = "AQAB".to_string();
    let jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE3NTM2NzY2NTg3NjciLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiI3MTM4NTEzMDI2ODYtc3ZsdWVqZDhsaTFsNXFkOXNwODA2dGJtazNsa2I0aGouYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDUwNDM4ODExNzc4ODQ3MzgyMjciLCJlbWFpbCI6ImtpbS5reXVuZ2tvb0BnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibm9uY2UiOiIweGEyYjkxZjgwMzA2MGIxNWUwMzVhM2Y2OTJmNDQ5ZThlODVmNjA1ZWRhYmMyZWFmNWM1ZWEzZDUwOTE5NWNmNCIsIm5hbWUiOiJLeXVuZ0tvbyBLaW0iLCJpYXQiOjE3NTM2NzY2NTgsImV4cCI6MTc1MzY4MDI1OX0.qOxUaUjKuaxcH4MmlqrMyK0kxjMIQ_SPhsE4mYbaR44mn7K8L5wvNpXADrXkAsIsf9ZkEv8rLuuhBFZBdJbI4dBEh_xFRHlcMn35IZPtbvLeDGbyqjg6uKTVpHG0z1j2_AkPIWwcUHqjxZ3Vs_y2W6O232Lics3rM45BdUh4-cJwoiez057-X7f3wmUCHxZ5psawVZ41P4HvfLfiBKu-ZZJvKUvoBHRp9vt93MMAys0i4YCAvGKFUi656rp9mN2kE2Km7JWns41tLMtOo0Pnh0mwJJQDDKFywABc10qdj_dDc_Z70Hjx_piUvHK_m1FOvNTIzWHOxBE59ffX4_xQPA".to_string();
    (jwt, n, e)
}

/// 테스트용 Anchor Key 생성
fn create_test_anchor_key(path: &PathBuf) {
    use ark_std::rand::rngs::OsRng;
    use common::gadget::anchor::poseidon::PoseidonAnchorScheme;

    let mut rng = OsRng;
    let n = 5;
    let k = 3;

    let pk: common::gadget::anchor::poseidon::PoseidonAnchorPublicKey<AppField> =
        PoseidonAnchorScheme::setup(&mut rng, n).unwrap();

    let anchor_key_ext = PoseidonAnchorKeyExtension {
        anchor_key: pk,
        n,
        k,
        max_aud_len: Some(50),
        max_iss_len: Some(50),
        max_sub_len: 100,
    };

    save_key_uncompressed(path, &anchor_key_ext).unwrap();
}

/// 테스트용 Schnorr Key 생성
fn create_test_schnorr_key(path: &PathBuf) {
    use ark_std::rand::rngs::OsRng;
    use common_gadget::signature::SignatureScheme;
    use common_gadget::signature::schnorr::Schnorr;

    let mut rng = OsRng;
    let params = Schnorr::<AppCurve, Blake2>::setup::<_>(&mut rng).unwrap();
    let (vk, _) = Schnorr::<AppCurve, Blake2>::keygen(&params, &mut rng).unwrap();

    let schnorr_key_ext = SchnorrPublicKeyExtension { params, vk };

    save_key_uncompressed(path, &schnorr_key_ext).unwrap();
}

/// 테스트용 JWT 데이터 생성 (실제로는 유효한 JWT가 필요)
fn create_test_jwt_data() -> (String, String, Vec<String>, String, Vec<u8>, u32) {
    // 간단한 테스트용 데이터
    // 실제 테스트에서는 유효한 JWT와 서명이 필요합니다
    let jwt = r#"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwibm9uY2UiOiJ0ZXN0LW5vbmNlIiwic3ViIjoidGVzdC1zdWJqZWN0IiwiYXVkIjoidGVzdC1hdWRpZW5jZSJ9.test-signature"#.to_string();

    let pk = "test-public-key".to_string();

    // Merkle proof (간단한 테스트용)
    let mp = vec!["0".to_string(); 5];

    let root = "1".to_string();

    // 빈 서명 (실제로는 유효한 Schnorr 서명 필요)
    let signature = vec![0u8; 96]; // 임시 서명 데이터

    let leaf_index = 0u32;

    (jwt, pk, mp, root, signature, leaf_index)
}

#[test]
#[ignore] // 실제 키와 데이터가 필요하므로 기본적으로는 무시
fn test_groth16_setup() {
    // 1. 테스트 디렉토리 설정
    let test_dir = setup_test_dir();

    // 2. 테스트용 키 파일 생성
    let anchor_key_path = test_dir.join("test_anchor_key.bin");
    let schnorr_key_path = test_dir.join("test_schnorr_key.bin");
    let pk_path = test_dir.join("test_proving_key.bin");

    create_test_anchor_key(&anchor_key_path);
    create_test_schnorr_key(&schnorr_key_path);

    // 3. .env 파일 설정 (Solidity verifier 경로)
    unsafe {
        std::env::set_var(
            "SOLIDITY_VERIFIER_PATH",
            test_dir.join("verifier.sol").to_str().unwrap(),
        );
    }

    // 4. Proving Key 생성
    let result = generate_and_write_proving_key(
        anchor_key_path.to_str().unwrap().to_string(),
        schnorr_key_path.to_str().unwrap().to_string(),
        512, // max_jwt_len
        256, // max_payload_len
        50,  // max_aud_len
        50,  // max_iss_len
        50,  // max_nonce_len
        100, // max_sub_len
        5,   // tree_height
        pk_path.to_str().unwrap().to_string(),
    );

    // 5. 결과 검증
    assert!(
        result.is_ok(),
        "Proving key generation failed: {:?}",
        result.err()
    );
    assert!(pk_path.exists(), "Proving key file not created");

    // 6. Proving Key 로드 테스트
    let pk_ext = load_key_uncompressed::<ProvingKeyExtension<BN254>>(&pk_path);
    assert!(pk_ext.is_ok(), "Failed to load proving key");

    let pk_ext = pk_ext.unwrap();
    assert_eq!(pk_ext.max_jwt_len, 512);
    assert_eq!(pk_ext.max_payload_len, 256);
    assert_eq!(pk_ext.tree_height, 5);

    println!("✓ Groth16 setup test passed");
}

#[test]
#[ignore] // 실제 키와 JWT 데이터가 필요하므로 기본적으로는 무시
fn test_groth16_prove_and_verify() {
    // 1. 테스트 디렉토리 및 파일 경로 설정
    let test_dir = setup_test_dir();
    let anchor_key_path = test_dir.join("test_anchor_key.bin");
    let schnorr_key_path = test_dir.join("test_schnorr_key.bin");
    let pk_path = test_dir.join("test_proving_key.bin");

    // 2. Setup이 이미 완료되어 있다고 가정 (또는 먼저 setup 실행)
    // test_groth16_setup()를 먼저 실행하거나 여기서 다시 실행

    // 3. 테스트용 witness 데이터 준비
    let anchor_parts = vec!["1".to_string(), "2".to_string(), "3".to_string()];

    let selected_secrets = vec![SecretDto {
        sub: Some("test-subject".to_string()),
        iss: Some("https://example.com".to_string()),
        aud: Some("test-audience".to_string()),
    }];

    let (jwt, pk, mp, root, signature, leaf_index) = create_test_jwt_data();

    let selector = vec![true, false, true, false, false]; // 5개 중 2개 선택
    let counter = "1".to_string();
    let random = "12345".to_string();
    let h_userop = "67890".to_string();
    let slot = 0usize;

    // 4. 증명 생성
    let proof_result = generate_proof(
        pk_path.to_str().unwrap().to_string(),
        anchor_key_path.to_str().unwrap().to_string(),
        schnorr_key_path.to_str().unwrap().to_string(),
        anchor_parts,
        selected_secrets,
        jwt,
        pk,
        mp,
        root,
        signature,
        leaf_index,
        selector,
        counter,
        random,
        h_userop,
        slot,
    );

    // 5. 증명 생성 결과 검증
    if let Err(e) = &proof_result {
        println!("Proof generation error: {:?}", e);
    }
    assert!(proof_result.is_ok(), "Proof generation failed");

    let (proof, public_inputs) = proof_result.unwrap();

    // 6. 증명 직렬화 테스트
    let mut proof_bytes = Vec::new();
    proof.serialize_uncompressed(&mut proof_bytes).unwrap();
    assert!(!proof_bytes.is_empty(), "Proof serialization failed");

    println!("✓ Proof generated successfully");
    println!("  - Proof size: {} bytes", proof_bytes.len());
    println!("  - Public inputs count: {}", public_inputs.len());

    // 7. 검증 (verify_proof 함수가 구현되면)
    // Note: verify_proof는 아직 unimplemented!() 상태입니다
    // 구현되면 다음과 같이 테스트할 수 있습니다:
    /*
    let vk_bytes = ...; // Verifying Key 로드
    let public_inputs_str: Vec<String> = public_inputs
        .iter()
        .map(|f| f.to_string())
        .collect();

    let verify_result = verify_proof(vk_bytes, proof_bytes, public_inputs_str);
    assert!(verify_result.is_ok());
    assert!(verify_result.unwrap(), "Proof verification failed");
    */
}

#[test]
fn test_key_serialization() {
    // 키 직렬화/역직렬화 테스트
    let test_dir = setup_test_dir();
    let anchor_key_path = test_dir.join("test_anchor_serialize.bin");

    // 1. Anchor Key 생성 및 저장
    create_test_anchor_key(&anchor_key_path);

    // 2. 로드
    let loaded = load_key_uncompressed::<PoseidonAnchorKeyExtension<AppField>>(&anchor_key_path);
    assert!(loaded.is_ok(), "Failed to load anchor key");

    let loaded = loaded.unwrap();
    assert_eq!(loaded.n, 5);
    assert_eq!(loaded.k, 3);
    assert_eq!(loaded.max_aud_len, Some(50));
    assert_eq!(loaded.max_iss_len, Some(50));
    assert_eq!(loaded.max_sub_len, 100);

    println!("✓ Key serialization test passed");
}

#[test]
fn test_anchor_creation() {
    // Anchor 생성 테스트
    let anchor_parts = vec![
        "123456789".to_string(),
        "987654321".to_string(),
        "111111111".to_string(),
    ];

    let result = build_poseidon_anchor_from_strings(&anchor_parts);
    assert!(result.is_ok(), "Failed to build anchor from strings");

    let (anchor, hanchor) = result.unwrap();
    assert_eq!(anchor.0.len(), anchor_parts.len() - 1); // 마지막 요소는 hanchor

    println!("✓ Anchor creation test passed");
    println!("  - Anchor hash: {:?}", hanchor);
}
