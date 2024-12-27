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

use std::mem::size_of;

pub fn lvw<W: std::io::Write + ?Sized>(
    w: &mut W,
    val: &[u8],
) -> std::io::Result<()> {
    let len_bytes = (val.len() as u64).to_le_bytes();
    w.write_all(&len_bytes)?;
    w.write_all(val)
}

pub fn lvr<R: std::io::Read + ?Sized>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; size_of::<u64>()];
    r.read_exact(&mut len_bytes)?;
    let len = u64::from_le_bytes(len_bytes);
    let mut v = vec![0u8; len as usize];
    r.read_exact(&mut v)?;
    Ok(v)
}
