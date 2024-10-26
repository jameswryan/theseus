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
use xoodyak::{XoodyakCommon, XoodyakHash};

use std::fmt::Display;

const DOMAIN_CHECKSUM: &[u8; 16] = b"THESEUS_CHECKSUM";
#[derive(Debug, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct TheseusChecksum {
    inner: [u8; 32],
}

impl ConstantTimeEq for TheseusChecksum {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.inner.ct_eq(&other.inner)
    }
}

impl PartialEq for TheseusChecksum {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Display for TheseusChecksum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", faster_hex::hex_string::<{ 32 * 2 }>(&self.inner))
    }
}

pub fn crypto_checksum(inp: &[u8]) -> TheseusChecksum {
    let mut hasher = XoodyakHash::new();
    hasher.absorb(DOMAIN_CHECKSUM);

    hasher.absorb(inp);
    let mut ck = [0u8; 32];
    hasher.squeeze(&mut ck);
    TheseusChecksum { inner: ck }
}
