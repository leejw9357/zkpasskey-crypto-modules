# TokenBuilder 사용 가이드

`TokenBuilder`는 JWT를 파싱하고 영지식 증명 회로(zero-knowledge circuit)에서 사용할 수 있는 다양한 구조체를 생성하는 빌더 패턴 API를 제공합니다.

## 주요 기능

TokenBuilder는 다음과 같은 구조체를 생성할 수 있습니다:
- `Token` - 기본 JWT 토큰 구조
- `TokenSig` - 서명 검증을 위한 구조 (signature, public key, SHA-256 state)
- `TokenPayloadB64` - Base64 디코딩을 위한 구조 (payload offset, length, bit witness)
- `ClaimIndices` - 개별 claim의 메타데이터 (offset, length, value position)

## 설치 및 Import

```rust
use crate::service::jwt::TokenBuilder;
use common_gadget::{
    jwt::{Token, error::TokenError},
    token::{
        signature::TokenSig,
        decode::TokenPayloadB64,
        claim::ClaimIndices,
    },
};
```

## 기본 사용법

### 1. Token 생성

기본적인 JWT 파싱과 claim 추출:

```rust
let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzNDU2Nzg5MCIsIm5vbmNlIjoiYWJjMTIzIn0.signature";
let n = "base64_encoded_rsa_modulus";

let token = TokenBuilder::new(jwt, n)
    .add_claim("iss")
    .add_claim("sub")
    .add_claim("nonce")
    .build()?;

// 또는 여러 claim을 한번에 추가
let token = TokenBuilder::new(jwt, n)
    .add_claims(&["iss", "sub", "nonce"])
    .build()?;
```

### 2. TokenSig 생성

서명 검증을 위한 회로 입력 생성:

```rust
let token_sig = TokenBuilder::new(jwt, n)
    .build_token_sig()?;

// 생성된 TokenSig 구조:
// - sig: RSA 서명
// - pk: RSA 공개키 (modulus, exponent)
// - state: SHA-256 중간 상태 (8 x u32)
// - nblocks: 처리된 SHA-256 블록 수
```

### 3. TokenPayloadB64 생성

Base64 디코딩을 위한 회로 입력 생성:

```rust
let max_jwt_len = 1024;      // JWT의 최대 길이
let max_payload_len = 512;    // 디코딩된 payload의 최대 길이

let token_payload = TokenBuilder::new(jwt, n)
    .build_token_payload_b64(max_jwt_len, max_payload_len)?;

// 생성된 TokenPayloadB64 구조:
// - pay_offset_b64: Base64 payload의 시작 오프셋
// - pay_len_b64: Base64 payload의 길이
// - sha_pad_payload_b64: SHA-256 패딩이 적용된 payload
// - bit_witness: Base64 디코딩을 위한 6비트 witness
```

### 4. ClaimIndices 생성

특정 claim의 위치 정보 추출:

```rust
// 단일 claim 인덱스
let nonce_indices = TokenBuilder::new(jwt, n)
    .build_claim_indices("nonce")?;

// 생성된 ClaimIndices 구조:
// - offset: claim의 시작 위치
// - claim_len: 전체 claim 길이 ("nonce":"abc123" 전체)
// - colon_idx: ':' 구분자의 위치
// - value_idx: 값의 시작 위치
// - value_len: 값의 길이

// 여러 claim 인덱스를 한번에
let indices = TokenBuilder::new(jwt, n)
    .add_claims(&["iss", "sub", "nonce"])
    .build_all_claim_indices()?;

// Vec<ClaimIndices> 반환 (등록한 claim 순서대로)
```

## 전체 예제

회로에 필요한 모든 구조를 생성하는 통합 예제:

```rust
use crate::service::jwt::TokenBuilder;

fn prepare_circuit_inputs(jwt: &str, n: &str) -> Result<(), TokenError> {
    // 1. 기본 Token 생성
    let token = TokenBuilder::new(jwt, n)
        .add_claims(&["iss", "sub", "nonce"])
        .build()?;
    
    // 2. 서명 검증용 TokenSig
    let token_sig = TokenBuilder::new(jwt, n)
        .build_token_sig()?;
    
    // 3. Base64 디코딩용 TokenPayloadB64
    let token_payload = TokenBuilder::new(jwt, n)
        .build_token_payload_b64(1024, 512)?;
    
    // 4. Claim 인덱스들
    let claim_indices = TokenBuilder::new(jwt, n)
        .add_claims(&["iss", "sub", "nonce"])
        .build_all_claim_indices()?;
    
    // 회로 입력으로 사용...
    Ok(())
}
```

## 메서드 체이닝 패턴

TokenBuilder는 빌더 패턴을 사용하므로 메서드 체이닝이 가능합니다:

```rust
let builder = TokenBuilder::new(jwt, n)
    .add_claim("iss")
    .add_claim("sub");

// 같은 builder로 여러 구조 생성 가능
let token = builder.clone().build()?;
let token_sig = builder.clone().build_token_sig()?;
let indices = builder.build_all_claim_indices()?;
```

## 주의사항

1. **메모리 제한**: `max_jwt_len`과 `max_payload_len`은 회로의 제약 조건에 맞게 설정해야 합니다.

2. **타입 변환**: `ClaimIndices`는 두 가지 타입이 있습니다:
   - `common_gadget::jwt::types::ClaimIndices` (필드명: `len`)
   - `common_gadget::token::claim::ClaimIndices` (필드명: `claim_len`)
   
   TokenBuilder는 자동으로 후자(`token::claim::ClaimIndices`)를 반환합니다.

3. **Base64 패딩**: `build_token_payload_b64()`는 Base64 'A' 문자 (0x00 값)로 패딩합니다.

4. **SHA-256 블록**: `build_token_sig()`는 64바이트 블록 단위로 SHA-256 상태를 계산합니다.

## 에러 처리

모든 빌드 메서드는 `Result<T, TokenError>`를 반환합니다:

```rust
match TokenBuilder::new(jwt, n).build() {
    Ok(token) => {
        // 성공
    }
    Err(TokenError::InvalidFormat(msg)) => {
        eprintln!("JWT 형식 오류: {}", msg);
    }
    Err(TokenError::NotFoundKeyError(key)) => {
        eprintln!("Claim 키를 찾을 수 없음: {}", key);
    }
    Err(e) => {
        eprintln!("기타 오류: {:?}", e);
    }
}
```

## 추가 정보

- 모든 빌드 메서드는 `self`를 소비(consume)하므로, 여러 번 사용하려면 `clone()`이 필요합니다.
- RSA 지수(exponent)는 기본값 "AQAB" (65537)를 사용합니다.
- Claim 키는 등록한 순서대로 처리됩니다.
