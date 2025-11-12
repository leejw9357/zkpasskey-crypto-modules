# ZKPasskey Crypto Modules Setup Guide

## Proving Key 생성

서비스 제공자는 시스템을 처음 설정할 때 한 번만 Proving Key를 생성해야 합니다.

### 필수 사항

Proving Key를 생성하기 전에 다음이 필요합니다:

1. **Anchor Key**: Poseidon Anchor Public Key 파일
2. **Schnorr Key**: Schnorr Public Key 파일
3. **환경 변수 설정**: `.env` 파일에 Solidity 출력 경로 설정

### 환경 변수 설정

먼저 프로젝트 루트에 `.env` 파일을 생성하고 다음 내용을 추가합니다:

```bash
# Solidity Verifier Contract Output Path
SOLIDITY_VERIFIER_PATH=./verifier/Groth16Verifier.sol
```

### 사용 방법

```rust
use zkpasskey_crypto_modules::service::snark::snark::generate_and_write_proving_key;

fn setup_proving_key() -> Result<(), ApplicationError> {
    // Proving Key 생성 및 Solidity Verifier 생성
    generate_and_write_proving_key(
        "path/to/anchor_key.bin".to_string(),      // Anchor Key 경로
        "path/to/schnorr_key.bin".to_string(),     // Schnorr Key 경로
        2048,                                       // max_jwt_len
        1024,                                       // max_payload_len
        256,                                        // max_aud_len
        256,                                        // max_iss_len
        256,                                        // max_nonce_len
        256,                                        // max_sub_len
        32,                                         // tree_height
        "path/to/output/proving_key.bin".to_string() // 출력 경로
    )?;
    
    Ok(())
}
```

이 함수는 다음 두 가지 파일을 생성합니다:
1. **Proving Key**: `out_path`에 지정된 경로에 저장
2. **Solidity Verifier**: `.env` 파일의 `SOLIDITY_VERIFIER_PATH`에 지정된 경로에 저장

### 파라미터 설명

- `anchor_key_path`: Poseidon Anchor Public Key 파일 경로
- `schnorr_key_path`: Schnorr Public Key 파일 경로
- `max_jwt_len`: 지원할 JWT의 최대 길이 (바이트)
- `max_payload_len`: JWT payload의 최대 길이 (바이트)
- `max_aud_len`: audience 필드의 최대 길이 (바이트)
- `max_iss_len`: issuer 필드의 최대 길이 (바이트)
- `max_nonce_len`: nonce 필드의 최대 길이 (바이트)
- `max_sub_len`: subject 필드의 최대 길이 (바이트)
- `tree_height`: Merkle tree의 높이
- `out_path`: 생성된 Proving Key를 저장할 경로

### 환경 변수

- `SOLIDITY_VERIFIER_PATH`: Solidity Verifier 컨트랙트를 저장할 경로 (필수)

### 주의사항

1. **한 번만 실행**: 이 함수는 서비스 제공자가 초기 설정 시 한 번만 실행합니다.
2. **긴 실행 시간**: Groth16 setup은 계산 집약적이며 완료까지 시간이 걸릴 수 있습니다.
3. **키 보안**: 생성된 Proving Key는 안전하게 보관해야 합니다.
4. **파라미터 선택**: 파라미터는 실제 사용 사례에 맞게 조정해야 합니다. 더 큰 값은 더 많은 계산 리소스가 필요합니다.

## 에러 처리

함수는 다음 에러를 반환할 수 있습니다:

- `KeyError::LoadFailed`: Key 파일을 로드하지 못함
- `KeyError::DeserializeFailed`: Key 역직렬화 실패
- `ApplicationError::SetupFailed`: Groth16 setup 실패
- `KeyError::SaveFailed`: Proving Key 저장 실패
- `ApplicationError::EnvVarNotFound`: 환경 변수 `SOLIDITY_VERIFIER_PATH`를 찾을 수 없음

## 예제 `.env` 파일

```bash
# Schnorr Secret Key (hex encoded, max 32 bytes)
SCHNORR_SECRET=your_secret_key_here

# Solidity Verifier Contract Output Path
SOLIDITY_VERIFIER_PATH=./verifier/Groth16Verifier.sol
```

---

## 증명 생성 (Proof Generation)

모바일 앱에서 사용자가 ZK 증명을 생성할 때 사용합니다.

### 메모리 최적화 설계

`generate_proof` 함수는 **파일 경로를 인자로 받도록** 설계되었습니다. 이는 모바일 환경의 제한된 메모리를 고려한 결정입니다:

#### 설계 근거

1. **메모리 효율성**
   - Proving Key는 매우 큼 (수백 MB ~ GB)
   - Handle 방식: 키가 메모리에 계속 상주 → 메모리 압박
   - File path 방식: 필요할 때만 로드, 사용 후 자동 해제 → 메모리 절약

2. **모바일 환경 특성**
   - 제한된 RAM (2-8GB)
   - 증명 생성은 비빈번한 작업
   - 로드 시간 < 메모리 부족 위험

3. **리소스 관리**
   - 각 증명 생성마다 독립적 메모리 관리
   - 가비지 컬렉션에 유리

### 사용 방법

```rust
use zkpasskey_crypto_modules::service::snark::snark::generate_proof;

fn create_proof() -> Result<Vec<u8>, ApplicationError> {
    // 증명 생성 (파일 경로 직접 전달)
    let proof_bytes = generate_proof(
        "./keys/proving_key.bin".to_string(),      // Proving Key 경로
        "./keys/anchor_key.bin".to_string(),       // Anchor Key 경로
        "./keys/schnorr_key.bin".to_string(),      // Schnorr Key 경로
        // TODO: witness 파라미터 추가
    )?;
    
    Ok(proof_bytes)
}
```

### 성능 고려사항

- **로드 시간**: 키 파일 로드에 1-3초 소요 (파일 크기에 따라)
- **메모리 피크**: 증명 생성 중에만 메모리 사용, 완료 후 해제
- **권장**: 증명 생성은 백그라운드 스레드에서 실행
