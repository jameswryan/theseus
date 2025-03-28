// Copyright 2024 James Ryan

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
use xoodyak::{
    XoodyakCommon, XoodyakHash, XoodyakKeyed, XOODYAK_AUTH_TAG_BYTES,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::{Zeroize, ZeroizeOnDrop};

use std::{
    fmt::Display,
    fs::File,
    io::{BufRead, BufReader, Read, Write},
    path::Path,
};

use crate::{error::*, provider::*};

const DOMAIN_HASH: &[u8; 8] = b"HASH____";
const DOMAIN_DERIVE: &[u8; 8] = b"DERIVE__";
const DOMAIN_ENCRYPT: &[u8; 8] = b"ENCRYPT_";
const DOMAIN_FKEYKEY: &[u8; 8] = b"FKEYKEY_";
const HASH_LEN: usize = 32;
const KEY_LEN: usize = 16;
const TAG_LEN: usize = XOODYAK_AUTH_TAG_BYTES;
const SALT_LEN: usize = 16;
const MAGIC_LEN: usize = 16;
const ENCHDR_MAGIC: &[u8; MAGIC_LEN] = b"THESEUS_ENCFILE_";

/// A cryptographic hash
#[derive(Debug, Eq, Clone, Copy, Serialize, Deserialize, Zeroize)]
pub struct TheseusHash([u8; HASH_LEN]);

impl ConstantTimeEq for TheseusHash {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for TheseusHash {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Display for TheseusHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            const_hex::const_encode::<HASH_LEN, false>(&self.0).as_str()
        )
    }
}

/// Compute a cryptographic hash of the input
pub fn crypto_hash(inp: &[u8]) -> TheseusHash {
    let mut hasher = XoodyakHash::new();
    hasher.absorb(DOMAIN_HASH);

    hasher.absorb(inp);
    let mut ck = [0u8; HASH_LEN];
    hasher.squeeze(&mut ck);
    TheseusHash(ck)
}

/// Run a key derivation function over the input and return a cryptographically
/// secure derived key
///
/// This function is **not** intended to resist password cracking attempts, and
/// such a function is not provided
pub fn crypto_kdf<IT: IntoIterator<Item = impl AsRef<[u8]>>>(
    inps: IT,
) -> TheseusKey {
    let mut hasher = XoodyakHash::new();
    hasher.absorb(DOMAIN_DERIVE);

    for inp in inps {
        hasher.absorb(inp.as_ref());
    }
    let mut ck = [0u8; KEY_LEN];
    hasher.squeeze_key(&mut ck);
    TheseusKey(ck)
}

/// Read uniformly random bytes from the system CSPRNG into `out`
///
/// These bytes are suitable for use in a cryptographic key
pub fn crypto_randbytes(out: &mut [u8]) -> Result<(), TheseusError> {
    let mut rng_dev = File::open("/dev/random")?;
    rng_dev.read_exact(out)?;
    Ok(())
}

/// Read `n` uniformly random bytes from the system CSPRNG and return them
///
/// These bytes are suitable for use in a cryptographic key
pub fn crypto_randvec(n: usize) -> Result<Vec<u8>, TheseusError> {
    let mut out = vec![0u8; n];
    crypto_randbytes(&mut out)?;
    Ok(out)
}

fn new_entropy() -> std::io::Result<[u8; 16]> {
    let mut e = [0u8; 16];
    getrandom::fill(&mut e)?;
    Ok(e)
}

#[derive(ZeroizeOnDrop, Clone)]
pub struct TheseusKey([u8; KEY_LEN]);

impl TheseusKey {
    /// Create a new key from a cryptographically secure entropy source
    pub fn from_entropy() -> Result<Self, TheseusError> {
        Ok(Self(new_entropy()?))
    }

    /// Create a new key from a raw byte array
    ///
    /// Zeros the provided byte array after copying the data
    pub fn from_raw(raw: &mut [u8; KEY_LEN]) -> Self {
        let s = Self(*raw);
        raw[..].zeroize();
        s
    }

    /// Create a key from a `KeyProvider` url.
    ///
    /// If the output of the provider is deterministic, so is this function
    pub fn from_provider(url: impl AsRef<str>) -> Result<Self, TheseusError> {
        let prov_out = theseus_getkey(url.as_ref())?;
        Ok(crypto_kdf([prov_out.as_bytes()]))
    }

    /// Derive a new key from this key using salt `salt`
    ///
    /// This function is deterministic
    pub fn derive_cryptokey(&self, salt: [u8; 16]) -> Self {
        crypto_kdf([&self.0, &salt])
    }

    /// Serialize this key to UTF-8 encoded hex string
    pub fn to_hex(self) -> Vec<u8> {
        let out = const_hex::const_encode::<KEY_LEN, false>(&self.0);
        out.to_vec()
    }
}

/// Encrypt in-place with a random key, returning the key
///
/// Requires that enough room for the tag (`TAG_LEN`) be left at the end of
/// the buffer
fn crypto_encrypt_in_place(
    inout: &mut [u8],
) -> Result<TheseusKey, TheseusError> {
    let key = TheseusKey::from_entropy()?;
    let mut cipher =
        XoodyakKeyed::new(&key.0, None, Some(DOMAIN_ENCRYPT), None)
            .or(Err(TheseusError::Crypto))?;
    cipher
        .aead_encrypt_in_place(inout)
        .or(Err(TheseusError::Crypto))?;

    Ok(key)
}

/// Decrypt in-place with key `key`
fn crypto_decrypt_in_place(
    inout: &mut [u8],
    key: &TheseusKey,
) -> Result<(), TheseusError> {
    let mut cipher =
        XoodyakKeyed::new(&key.0, None, Some(DOMAIN_ENCRYPT), None)
            .or(Err(TheseusError::Crypto))?;
    cipher
        .aead_decrypt_in_place(inout)
        .or(Err(TheseusError::Crypto))?;
    Ok(())
}

/// Ensure header has size HEADER_SIZE (in bytes)
const HEADER_SIZE: usize = 128;
const _: () =
    [(); 1][(core::mem::size_of::<Header>() == HEADER_SIZE) as usize ^ 1];

/// On-disk header for encrypted file format
#[derive(
    FromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq, Debug,
)]
#[repr(C, packed)]
struct Header {
    /* If new fields need to be authenticated, put them *before* _unused */
    /* If they don't need authentication, put them after _unused :) */
    /// Header magic bytes
    magic: [u8; MAGIC_LEN],
    /// Version of the on-disk format
    version: u8,
    /// Padding :)
    _unused: [u8; HEADER_SIZE
        - MAGIC_LEN
        - size_of::<u8>()
        - SALT_LEN
        - TAG_LEN
        - KEY_LEN],
    /// Salt for file key
    salt: [u8; SALT_LEN],
    /// Header authentication tag
    htag: [u8; TAG_LEN],
    /// Encrypted file key
    ekey: [u8; KEY_LEN],
}

impl Header {
    /// Header current version
    const HCV: u8 = 0;

    /// Amount of space in the header not currently used
    const FREE: usize =
        HEADER_SIZE - MAGIC_LEN - TAG_LEN - 16 - KEY_LEN - size_of::<u8>();

    /// Create a new header at the current version
    fn new(mkey: &TheseusKey, fkey: &TheseusKey) -> Result<Self, TheseusError> {
        /* Concatenate new header fields to ad */
        let mut ad = ENCHDR_MAGIC.to_vec();
        ad.extend(Self::HCV.to_le_bytes());

        let salt = new_entropy()?;
        let fkeykey = mkey.derive_cryptokey(salt);
        let mut cipher = XoodyakKeyed::new(
            &fkeykey.0,
            Some(&ad),
            Some(DOMAIN_FKEYKEY),
            None,
        )
        .or(Err(TheseusError::Crypto))?;

        let mut ekey = fkey.clone();
        let htag = cipher.aead_encrypt_in_place_detached(&mut ekey.0).into();

        Ok(Self {
            magic: *ENCHDR_MAGIC,
            htag,
            salt,
            ekey: ekey.0,
            version: Self::HCV,
            _unused: [0u8; Self::FREE],
        })
    }

    /// Decrypt and return the file key
    fn get_fkey(&self, mkey: &TheseusKey) -> Result<TheseusKey, TheseusError> {
        /* Concatenate new header fields to ad */
        let mut ad = self.magic.to_vec();
        ad.extend(self.version.to_le_bytes());

        let fkeykey = mkey.derive_cryptokey(self.salt);
        let mut fkey = self.ekey;
        let mut cipher = XoodyakKeyed::new(
            &fkeykey.0,
            Some(&ad),
            Some(DOMAIN_FKEYKEY),
            None,
        )
        .or(Err(TheseusError::Crypto))?;
        cipher
            .aead_decrypt_in_place_detached(&mut fkey, &self.htag.into())
            .or(Err(TheseusError::Crypto))?;

        Ok(TheseusKey::from_raw(&mut fkey))
    }

    /// Convert bytes into a header
    ///
    /// Checks that the header is *semantically* valid.
    /// That is, checks that the header tag authenticates the header
    fn from_bytes(
        raw: [u8; HEADER_SIZE],
        mkey: &TheseusKey,
    ) -> Result<Self, TheseusError> {
        /* Read header */
        let maybe_self: Header = zerocopy::transmute!(raw);

        /* Concatenate new header fields to ad */
        let mut ad = maybe_self.magic.to_vec();
        ad.extend(maybe_self.version.to_le_bytes());

        let fkeykey = mkey.derive_cryptokey(maybe_self.salt);
        let mut cipher = XoodyakKeyed::new(
            &fkeykey.0,
            Some(&ad),
            Some(DOMAIN_FKEYKEY),
            None,
        )
        .or(Err(TheseusError::Crypto))?;

        let mut fkey = [0u8; KEY_LEN];
        cipher
            .aead_decrypt_detached(
                &mut fkey,
                &maybe_self.htag.into(),
                Some(&maybe_self.ekey),
            )
            .or(Err(TheseusError::Crypto))?;
        fkey[..].zeroize();

        Ok(maybe_self)
    }
}

/// Save `data` to writer, encrypting with `mkey`
pub fn encfile_write<W: std::io::Write>(
    mut w: W,
    mkey: &TheseusKey,
    mut data: Vec<u8>,
) -> Result<(), TheseusError> {
    data.extend_from_slice(&[0u8; TAG_LEN]);
    let fkey = crypto_encrypt_in_place(&mut data)?;

    let hdr = Header::new(mkey, &fkey)?;
    w.write_all(hdr.as_bytes())?;
    w.write_all(&data)?;
    w.flush()?;
    Ok(())
}

/// Read encrypted file from `r`, decrypting with `mkey`
///
/// On success, returns *decrypted* file
pub fn encfile_read<R: std::io::Read>(
    mut r: R,
    mkey: &TheseusKey,
) -> Result<Vec<u8>, TheseusError> {
    let mut hdr_bytes = [0u8; HEADER_SIZE];
    r.read_exact(&mut hdr_bytes)?;
    let hdr = Header::from_bytes(hdr_bytes, mkey)?;
    let mut data = Vec::new();
    r.read_to_end(&mut data)?;

    let fkey = hdr.get_fkey(mkey)?;
    crypto_decrypt_in_place(&mut data, &fkey)?;
    data.truncate(data.len() - TAG_LEN);

    Ok(data)
}

/// Encrypt a file in-place using key `mkey`
pub fn encrypt_in_place(
    p: &Path,
    mkey: &TheseusKey,
) -> Result<(), TheseusError> {
    let data = std::fs::read(p)?;
    let f = File::create(p)?;
    encfile_write(f, mkey, data)?;
    Ok(())
}

/// Decrypt a file in-place using key `mkey`
pub fn decrypt_in_place(
    p: &Path,
    mkey: &TheseusKey,
) -> Result<(), TheseusError> {
    let r = File::open(p)?;
    let data = encfile_read(r, mkey)?;
    Ok(File::create(p)?.write_all(&data)?)
}

/// Check if `r` reads a file encrypted with `mkey`
pub fn is_encrypted<R: std::io::Read>(
    r: R,
    mkey: Option<&TheseusKey>,
) -> Result<bool, TheseusError> {
    let mut b = BufReader::new(r);
    let fstart = b.fill_buf()?;
    if !fstart.starts_with(ENCHDR_MAGIC) {
        return Ok(false);
    }

    let Some(mkey) = mkey else {
        return Err(TheseusError::NoKey("in-memory reader".to_string()));
    };

    let mut hdr_bytes = [0u8; HEADER_SIZE];
    b.read_exact(&mut hdr_bytes)?;
    match Header::from_bytes(hdr_bytes, mkey) {
        Ok(_) => Ok(true),
        Err(e) => match e {
            TheseusError::Crypto => Ok(false),
            e => Err(e),
        },
    }
}

/// Change the master key for `p` in-place
///
/// Also changes the file encryption key and salt
pub fn rekey_in_place(
    p: &Path,
    from: &TheseusKey,
    to: &TheseusKey,
) -> Result<(), TheseusError> {
    let fpt = encfile_read(File::open(p)?, from)?;
    encfile_write(File::create(p)?, to, fpt)
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::TmpDir;

    #[test]
    fn test_hash_is_xoodyak() {
        let inp = [0u8; 16];
        let exp = [
            0xb8, 0x68, 0x19, 0xd3, 0xab, 0x1a, 0x53, 0x1d, 0xf8, 0xec, 0x8c,
            0xf6, 0x20, 0xf8, 0xb0, 0xd, 0x9f, 0xe7, 0x35, 0x64, 0x67, 0x66,
            0xba, 0x48, 0x6e, 0xdc, 0x6f, 0x7b, 0x8c, 0x72, 0x3b, 0x16,
        ];
        let out = crypto_hash(&inp);

        assert_eq!(out.0, exp);
    }

    #[test]
    fn test_kdf_is_xoodyak() {
        let inps = [[0u8; 16]; 16];
        let exp = [
            0xa1, 0x13, 0x84, 0xbd, 0xae, 0x3b, 0x19, 0xb3, 0x0f, 0xf5, 0x25,
            0xb6, 0x85, 0x12, 0x7b, 0xde,
        ];
        let out = crypto_kdf(inps);
        assert_eq!(out.0, exp);
    }

    #[test]
    fn header_tobytes_frombytes() -> Result<(), Box<dyn std::error::Error>> {
        let mkey = TheseusKey::from_entropy()?;
        let fkey = TheseusKey::from_entropy()?;

        let hdr = Header::new(&mkey, &fkey)?;
        let mut hdr_bytes = [0u8; HEADER_SIZE];
        hdr_bytes.copy_from_slice(hdr.as_bytes());
        let hdr_rcnstrct = Header::from_bytes(hdr_bytes, &mkey)?;
        assert_eq!(hdr, hdr_rcnstrct);
        Ok(())
    }

    #[test]
    fn encfile_read_write() -> Result<(), Box<dyn std::error::Error>> {
        let mkey = TheseusKey::from_entropy()?;
        let file = vec![1u8; 256];
        let mut efile = Vec::new();
        encfile_write(&mut efile, &mkey, file.clone())?;
        let pfile = encfile_read(&efile[..], &mkey)?;
        assert_eq!(file, pfile);
        Ok(())
    }

    #[test]
    fn encfile_is_encrypted() -> Result<(), Box<dyn std::error::Error>> {
        let mkey = TheseusKey::from_entropy()?;
        let file = vec![1u8; 256];
        let mut efile = Vec::new();
        encfile_write(&mut efile, &mkey, file.clone())?;
        assert!(is_encrypted(&efile[..], Some(&mkey))?);
        Ok(())
    }

    #[test]
    fn encfile_is_not_encrypted_with_different_key(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mkey = TheseusKey::from_entropy()?;
        let not_mkey = TheseusKey::from_entropy()?;
        let file = vec![1u8; 256];
        let mut efile = Vec::new();
        encfile_write(&mut efile, &mkey, file.clone())?;
        assert!(!is_encrypted(&efile[..], Some(&not_mkey))?);
        Ok(())
    }

    #[test]
    fn encfile_modified_version_is_not_encrypted(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mkey = TheseusKey::from_entropy()?;
        let file = vec![1u8; 256];
        let mut efile = Vec::new();
        encfile_write(&mut efile, &mkey, file.clone())?;
        crypto_randbytes(&mut efile[MAGIC_LEN..MAGIC_LEN + 1])?;
        assert!(!is_encrypted(&efile[..], Some(&mkey))?);
        Ok(())
    }

    #[test]
    fn encrypt_decrypt_in_place_is_id() -> Result<(), Box<dyn std::error::Error>>
    {
        let td = TmpDir::new()?;
        let tf = td.as_ref().join("data.txt");
        let data = vec![1u8; 256];
        std::fs::write(&tf, &data)?;
        let key = TheseusKey::from_entropy()?;
        encrypt_in_place(&tf, &key)?;
        assert!(is_encrypted(File::open(&tf)?, Some(&key))?);
        decrypt_in_place(&tf, &key)?;
        let _data = std::fs::read(&tf)?;
        assert_eq!(data, _data);
        Ok(())
    }

    #[test]
    fn rekey_changes_keys() -> Result<(), Box<dyn std::error::Error>> {
        let td = TmpDir::new()?;
        let tf = td.as_ref().join("data.txt");
        let data = vec![1u8; 256];
        let from = TheseusKey::from_entropy()?;
        let to = TheseusKey::from_entropy()?;
        std::fs::write(&tf, &data)?;
        encrypt_in_place(&tf, &from)?;
        assert!(is_encrypted(File::open(&tf)?, Some(&from))?);
        rekey_in_place(&tf, &from, &to)?;
        assert!(is_encrypted(File::open(&tf)?, Some(&to))?);
        Ok(())
    }
}
