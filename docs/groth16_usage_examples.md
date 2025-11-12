# Groth16 사용 예제

이 문서는 Groth16 영지식 증명 시스템을 실제로 사용하는 방법을 단계별로 설명합니다.

## 전제 조건

1. Anchor Key가 생성되어 있어야 합니다
2. Schnorr Key가 생성되어 있어야 합니다
3. `.env` 파일에 환경 변수가 설정되어 있어야 합니다

## 1단계: Setup (한 번만 실행)

Proving Key와 Verifying Key를 생성합니다. 이 작업은 시간이 오래 걸리며 (수 분~수십 분) 한 번만 수행하면 됩니다.

```rust
use zkpasskey_crypto_modules::service::snark::snark::generate_and_write_proving_key;

fn setup_groth16() -> Result<(), Box<dyn std::error::Error>> {
    // 파라미터 설정
    let max_jwt_len = 1024;      // JWT 최대 길이
    let max_payload_len = 512;   // Payload 최대 길이
    let max_aud_len = 100;       // Audience 최대 길이
    let max_iss_len = 100;       // Issuer 최대 길이
    let max_nonce_len = 100;     // Nonce 최대 길이
    let max_sub_len = 200;       // Subject 최대 길이
    let tree_height = 10;        // Merkle tree 높이 (2^10 = 1024 leaves)

    // Proving Key 생성 및 저장
    generate_and_write_proving_key(
        "keys/anchor_key.bin".to_string(),
        "keys/schnorr_key.bin".to_string(),
        max_jwt_len,
        max_payload_len,
        max_aud_len,
        max_iss_len,
        max_nonce_len,
        max_sub_len,
        tree_height,
        "keys/proving_key.bin".to_string(),
    )?;

    println!("✓ Proving Key generated successfully");
    println!("✓ Solidity Verifier generated at: {}", 
             std::env::var("SOLIDITY_VERIFIER_PATH")?);

    Ok(())
}
```

## 2단계: Witness 준비

증명을 생성하기 위한 witness 데이터를 준비합니다.

```rust
use zkpasskey_crypto_modules::interface::anchor::SecretDto;

fn prepare_witness() -> WitnessData {
    // 1. Anchor 데이터
    let anchor_parts = vec![
        "123456789012345678901234567890".to_string(),
        "987654321098765432109876543210".to_string(),
        "555555555555555555555555555555".to_string(),
        "999999999999999999999999999999".to_string(), // hanchor
    ];

    // 2. 선택된 시크릿 (k개)
    let selected_secrets = vec![
        SecretDto {
            sub: Some("user@example.com".to_string()),
            iss: Some("https://accounts.google.com".to_string()),
            aud: Some("my-app-id".to_string()),
        },
        SecretDto {
            sub: Some("another-user@example.com".to_string()),
            iss: Some("https://accounts.google.com".to_string()),
            aud: Some("my-app-id".to_string()),
        },
    ];

    // 3. JWT 토큰 (실제 유효한 JWT)
    let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...".to_string();

    // 4. 공개 키 (RSA 또는 ECDSA)
    let pk = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string();

    // 5. Merkle proof
    let merkle_proof = vec![
        "12345678901234567890123456789012".to_string(),
        "98765432109876543210987654321098".to_string(),
        // ... tree_height만큼의 형제 노드들
    ];

    // 6. Merkle root
    let root = "11111111111111111111111111111111".to_string();

    // 7. Schnorr 서명 (바이트 배열)
    let signature: Vec<u8> = vec![/* ... */];

    // 8. Leaf index (Merkle tree에서의 위치)
    let leaf_index = 42u32;

    // 9. Selector (어떤 시크릿을 선택했는지)
    let selector = vec![true, true, false, false, false]; // 처음 2개 선택

    // 10. 기타 파라미터들
    let counter = "1".to_string();
    let random = "98765432109876543210".to_string();
    let h_userop = "11111111111111111111".to_string();
    let slot = 0usize;

    WitnessData {
        anchor_parts,
        selected_secrets,
        jwt,
        pk,
        merkle_proof,
        root,
        signature,
        leaf_index,
        selector,
        counter,
        random,
        h_userop,
        slot,
    }
}

struct WitnessData {
    anchor_parts: Vec<String>,
    selected_secrets: Vec<SecretDto>,
    jwt: String,
    pk: String,
    merkle_proof: Vec<String>,
    root: String,
    signature: Vec<u8>,
    leaf_index: u32,
    selector: Vec<bool>,
    counter: String,
    random: String,
    h_userop: String,
    slot: usize,
}
```

## 3단계: 증명 생성

준비한 witness 데이터로 증명을 생성합니다.

```rust
use zkpasskey_crypto_modules::service::snark::snark::generate_proof;
use ark_serialize::CanonicalSerialize;

fn create_proof(witness: WitnessData) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    println!("Generating proof...");
    
    let (proof, public_inputs) = generate_proof(
        "keys/proving_key.bin".to_string(),
        "keys/anchor_key.bin".to_string(),
        "keys/schnorr_key.bin".to_string(),
        witness.anchor_parts,
        witness.selected_secrets,
        witness.jwt,
        witness.pk,
        witness.merkle_proof,
        witness.root,
        witness.signature,
        witness.leaf_index,
        witness.selector,
        witness.counter,
        witness.random,
        witness.h_userop,
        witness.slot,
    )?;

    println!("✓ Proof generated successfully");
    println!("  Public inputs: {} elements", public_inputs.len());

    // 증명을 바이트 배열로 직렬화
    let mut proof_bytes = Vec::new();
    proof.serialize_uncompressed(&mut proof_bytes)?;
    
    println!("  Proof size: {} bytes", proof_bytes.len());

    // 공개 입력도 문자열로 변환
    let public_inputs_str: Vec<String> = public_inputs
        .iter()
        .map(|f| f.to_string())
        .collect();

    // 파일로 저장 (선택사항)
    std::fs::write("proof.bin", &proof_bytes)?;
    std::fs::write("public_inputs.json", 
                   serde_json::to_string_pretty(&public_inputs_str)?)?;

    Ok(proof_bytes)
}
```

## 4단계: 증명 검증 (구현 예정)

```rust
use zkpasskey_crypto_modules::service::snark::snark::verify_proof;

fn verify_proof_example(
    proof_bytes: Vec<u8>,
    public_inputs: Vec<String>,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Verifying Key 로드
    let vk_bytes = std::fs::read("keys/verifying_key.bin")?;

    // 증명 검증
    let is_valid = verify_proof(
        vk_bytes,
        proof_bytes,
        public_inputs,
    )?;

    if is_valid {
        println!("✓ Proof is VALID");
    } else {
        println!("✗ Proof is INVALID");
    }

    Ok(is_valid)
}
```

## 전체 예제

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup (최초 1회만)
    // setup_groth16()?;

    // 2. Witness 준비
    let witness = prepare_witness();

    // 3. 증명 생성
    let proof_bytes = create_proof(witness)?;

    // 4. 증명 검증 (구현 예정)
    // let public_inputs = serde_json::from_str(&std::fs::read_to_string("public_inputs.json")?)?;
    // verify_proof_example(proof_bytes, public_inputs)?;

    Ok(())
}
```

## 성능 고려사항

### Setup
- **시간**: Circuit 크기에 따라 수 분 ~ 수십 분
- **메모리**: 수 GB (대용량 Circuit의 경우)
- **디스크**: Proving Key는 수백 MB ~ 수 GB

### Prove
- **시간**: 수 초 ~ 수십 초 (Circuit 복잡도에 따라)
- **메모리**: Proving Key를 로드해야 하므로 수백 MB
- **최적화**: 모바일에서는 파일에서 직접 로드하여 메모리 사용 최소화

### Verify
- **시간**: 수 밀리초 (매우 빠름)
- **메모리**: Verifying Key는 매우 작음 (수 KB)
- **온체인**: Solidity로 검증 가능

## 보안 고려사항

1. **Proving Key 보호**: Proving Key는 공개되어도 괜찮지만 조작되어서는 안 됩니다
2. **Witness 기밀성**: Witness 데이터(특히 시크릿)는 절대 공개되어서는 안 됩니다
3. **랜덤성**: `random` 파라미터는 암호학적으로 안전한 난수를 사용해야 합니다
4. **서명 검증**: Schnorr 서명이 유효한지 먼저 확인해야 합니다
5. **JWT 검증**: JWT가 유효한지 먼저 확인해야 합니다

## 트러블슈팅

### "Circuit validation failed"
- Witness 데이터가 Circuit 제약조건을 만족하지 않음
- JWT 길이, Payload 길이 등이 설정한 최대값을 초과하지 않는지 확인
- selector의 true 개수가 k와 일치하는지 확인

### "Failed to load proving key"
- 파일 경로가 올바른지 확인
- 파일이 손상되지 않았는지 확인
- 충분한 메모리가 있는지 확인

### "Proof generation failed"
- Circuit이 만족되지 않음 (unsatisfied constraint)
- 각 입력 값이 올바른지 확인
- Merkle proof가 유효한지 확인

## 참고 자료

- [Memory Optimization Guide](../docs/memory_optimization.md)
- [Setup Guide](../docs/setup_guide.md)
- [Groth16 Integration Tests](./README.md)
