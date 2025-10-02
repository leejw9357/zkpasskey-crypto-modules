use std::{fs::File, io::Cursor, path::Path, sync::Arc};

use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use memmap2::MmapOptions;

use crate::error::error::KeyError;

pub trait KeyLoadable: CanonicalDeserialize + Send + Sync + 'static {
    fn new_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    fn from_path(path: &Path, compress: bool, validate: bool) -> Result<Arc<Self>, KeyError> {
        let (compress, validate) = to_modes(compress, validate);
        let file = File::open(path)?;
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        let mut cur = Cursor::new(&mmap[..]);
        let key =
            <Self as CanonicalDeserialize>::deserialize_with_mode(&mut cur, compress, validate)?;
        Ok(Arc::new(key))
    }
}

impl<T> KeyLoadable for T where T: CanonicalDeserialize + Send + Sync + 'static {}

fn to_modes(c: bool, v: bool) -> (Compress, Validate) {
    (
        if c { Compress::Yes } else { Compress::No },
        if v { Validate::Yes } else { Validate::No },
    )
}
