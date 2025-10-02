use std::{fs::File, io::BufReader, path::Path};

use ark_serialize::CanonicalDeserialize;

use crate::error::error::KeyError;

pub fn load_key<P: AsRef<Path>, K: CanonicalDeserialize>(path: P) -> Result<K, KeyError> {
    // 1. 파일을 엽니다.
    let file = File::open(path)?;

    let mut reader = BufReader::new(file);

    let key = K::deserialize_compressed(&mut reader)?;

    Ok(key)
}
