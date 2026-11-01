use crate::config::ZERO64;
use aes::cipher::{KeyIvInit, StreamCipher};
use byteorder::{BigEndian, ByteOrder, LittleEndian};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

// ---------------------------------------------------------------------------
// TrackedStream — эмулирует Go cipher.Stream с поддержкой Clone() через
// копирование внутреннего состояния AES/CTR за O(1).
// ---------------------------------------------------------------------------

pub struct TrackedStream {
    stream: Aes256Ctr,
}

impl TrackedStream {
    pub fn new(key: &[u8], iv: &[u8]) -> TrackedStream {
        let stream = Aes256Ctr::new(key.into(), iv.into());
        TrackedStream { stream }
    }

    // XOR in place (dst == src в нашем использовании)
    pub fn xor(&mut self, data: &mut [u8]) {
        self.stream.apply_keystream(data);
    }

    pub fn clone_state(&self) -> TrackedStream {
        TrackedStream {
            stream: self.stream.clone(),
        }
    }
}

pub fn new_aes_ctr(key: &[u8], iv: &[u8]) -> TrackedStream {
    TrackedStream::new(key, iv)
}

// ---------------------------------------------------------------------------
// MTProto Splitter
// ---------------------------------------------------------------------------

pub const PROTO_ABRIDGED: i32 = 0;
pub const PROTO_INTERMEDIATE: i32 = 1;
pub const PROTO_PADDED_INTERMEDIATE: i32 = 2;

pub fn proto_tag_to_type(proto: u32) -> i32 {
    match proto {
        0xEEEEEEEE => PROTO_INTERMEDIATE,
        0xDDDDDDDD => PROTO_PADDED_INTERMEDIATE,
        _ => PROTO_ABRIDGED,
    }
}

pub struct MsgSplitter {
    stream: Aes256Ctr,
    proto_type: i32,
    cipher_buf: Vec<u8>,
    plain_buf: Vec<u8>,
    disabled: bool,
}

impl MsgSplitter {
    pub fn new(init_data: &[u8], proto: u32) -> Option<MsgSplitter> {
        if init_data.len() < 56 {
            return None;
        }
        let mut stream = Aes256Ctr::new(init_data[8..40].into(), init_data[40..56].into());
        let mut skip = [0u8; 64];
        skip.copy_from_slice(&ZERO64);
        stream.apply_keystream(&mut skip);
        Some(MsgSplitter {
            stream,
            proto_type: proto_tag_to_type(proto),
            cipher_buf: Vec::new(),
            plain_buf: Vec::new(),
            disabled: false,
        })
    }

    pub fn split(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        if chunk.is_empty() {
            return Vec::new();
        }
        if self.disabled {
            return vec![chunk.to_vec()];
        }

        self.cipher_buf.extend_from_slice(chunk);
        let mut decrypted = chunk.to_vec();
        self.stream.apply_keystream(&mut decrypted);
        self.plain_buf.extend_from_slice(&decrypted);

        self.drain_packets()
    }

    /// Fast bridge path: the client plaintext is already available, so no third AES pass.
    pub fn split_plaintext(
        &mut self,
        chunk: &mut [u8],
        encryptor: &mut TrackedStream,
    ) -> Vec<Vec<u8>> {
        if self.disabled {
            encryptor.xor(chunk);
            return vec![chunk.to_vec()];
        }
        self.plain_buf.extend_from_slice(chunk);
        encryptor.xor(chunk);
        self.cipher_buf.extend_from_slice(chunk);
        self.drain_packets()
    }

    fn drain_packets(&mut self) -> Vec<Vec<u8>> {
        // Порт MsgSplitter.split из proxy/bridge.py: идём по буферу с offset,
        // а не удаляем каждый пакет с начала (иначе O(N^2) на чанке с кучей
        // мелких пакетов). Один trailing del в конце — O(N).
        let mut parts: Vec<Vec<u8>> = Vec::new();
        let mut offset: usize = 0;
        let buf_len = self.cipher_buf.len();
        while offset < buf_len {
            let avail = buf_len - offset;
            let pkt_len = self.next_packet_len_at(offset, avail);
            match pkt_len {
                None => break,
                Some(0) => {
                    parts.push(self.cipher_buf[offset..].to_vec());
                    offset = buf_len;
                    self.disabled = true;
                    break;
                }
                Some(n) => {
                    parts.push(self.cipher_buf[offset..offset + n].to_vec());
                    offset += n;
                }
            }
        }

        if offset > 0 {
            self.cipher_buf.drain(..offset);
            self.plain_buf.drain(..offset);
        }
        parts
    }

    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.cipher_buf.is_empty() {
            return Vec::new();
        }
        let tail = self.cipher_buf.clone();
        self.cipher_buf.clear();
        self.plain_buf.clear();
        vec![tail]
    }

    fn next_packet_len_at(&self, offset: usize, avail: usize) -> Option<usize> {
        if avail == 0 || self.plain_buf.len() <= offset {
            return None;
        }
        match self.proto_type {
            PROTO_ABRIDGED => self.next_abridged_len_at(offset, avail),
            PROTO_INTERMEDIATE | PROTO_PADDED_INTERMEDIATE => {
                self.next_intermediate_len_at(offset, avail)
            }
            _ => Some(0),
        }
    }

    fn next_abridged_len_at(&self, offset: usize, avail: usize) -> Option<usize> {
        // Порт _next_abridged_len: long-form при first == 0x7F **или** 0xFF.
        let first = self.plain_buf[offset];
        let (header_len, payload_len) = if first == 0x7F || first == 0xFF {
            if avail < 4 {
                return None;
            }
            let payload = ((self.plain_buf[offset + 1] as usize)
                | ((self.plain_buf[offset + 2] as usize) << 8)
                | ((self.plain_buf[offset + 3] as usize) << 16))
                * 4;
            (4usize, payload)
        } else {
            let payload = (first as usize & 0x7F) * 4;
            (1usize, payload)
        };
        if payload_len == 0 {
            return Some(0);
        }
        let pkt_len = header_len + payload_len;
        if avail < pkt_len {
            return None;
        }
        Some(pkt_len)
    }

    fn next_intermediate_len_at(&self, offset: usize, avail: usize) -> Option<usize> {
        if avail < 4 {
            return None;
        }
        let payload_len =
            (LittleEndian::read_u32(&self.plain_buf[offset..offset + 4]) & 0x7FFFFFFF) as usize;
        if payload_len == 0 {
            return Some(0);
        }
        let pkt_len = 4 + payload_len;
        if avail < pkt_len {
            return None;
        }
        Some(pkt_len)
    }

    #[allow(dead_code)]
    fn next_packet_len(&self) -> i64 {
        if self.plain_buf.is_empty() {
            return -1;
        }
        match self.proto_type {
            PROTO_ABRIDGED => {
                let raw_first = self.plain_buf[0];
                let header_len;
                let payload_len;
                if raw_first == 0x7F || raw_first == 0xFF {
                    if self.plain_buf.len() < 4 {
                        return -1;
                    }
                    payload_len = ((self.plain_buf[1] as i64)
                        | ((self.plain_buf[2] as i64) << 8)
                        | ((self.plain_buf[3] as i64) << 16))
                        * 4;
                    header_len = 4;
                } else {
                    let first = raw_first & 0x7F;
                    payload_len = (first as i64) * 4;
                    header_len = 1;
                }
                if payload_len <= 0 {
                    return 0;
                }
                let pkt_len = header_len + payload_len;
                if (self.plain_buf.len() as i64) < pkt_len {
                    return -1;
                }
                pkt_len
            }
            PROTO_INTERMEDIATE | PROTO_PADDED_INTERMEDIATE => {
                if self.plain_buf.len() < 4 {
                    return -1;
                }
                let payload_len =
                    (LittleEndian::read_u32(&self.plain_buf[..4]) & 0x7FFFFFFF) as i64;
                if payload_len <= 0 {
                    return 0;
                }
                let pkt_len = 4 + payload_len;
                if (self.plain_buf.len() as i64) < pkt_len {
                    return -1;
                }
                pkt_len
            }
            _ => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// XOR mask (websocket frame masking) — оптимизированный вариант
// ---------------------------------------------------------------------------

pub fn xor_mask_in_place(data: &mut [u8], mask: &[u8]) {
    let n = data.len();
    if n == 0 {
        return;
    }
    let mask8: u64 = (mask[0] as u64)
        | ((mask[1] as u64) << 8)
        | ((mask[2] as u64) << 16)
        | ((mask[3] as u64) << 24)
        | ((mask[0] as u64) << 32)
        | ((mask[1] as u64) << 40)
        | ((mask[2] as u64) << 48)
        | ((mask[3] as u64) << 56);

    let mut i = 0;
    while i + 8 <= n {
        let v = LittleEndian::read_u64(&data[i..]);
        LittleEndian::write_u64(&mut data[i..], v ^ mask8);
        i += 8;
    }
    while i < n {
        data[i] ^= mask[i & 3];
        i += 1;
    }
}

#[allow(dead_code)]
pub fn write_be_u16(buf: &mut [u8], v: u16) {
    BigEndian::write_u16(buf, v);
}
#[allow(dead_code)]
pub fn write_be_u64(buf: &mut [u8], v: u64) {
    BigEndian::write_u64(buf, v);
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    #[test]
    fn aes256_ctr_nist_vector_and_partial_clone() {
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap();
        let iv = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let mut data =
            hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
                .unwrap();
        let mut stream = new_aes_ctr(&key, &iv);
        stream.xor(&mut data[..7]);
        let mut cloned = stream.clone_state();
        let mut tail = data[7..].to_vec();
        cloned.xor(&mut tail);
        stream.xor(&mut data[7..]);
        assert_eq!(data[7..], tail);
        assert_eq!(
            hex::encode(data),
            "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
        );
    }
    #[test]
    fn ctr_carries_across_low_64_bits() {
        use aes::cipher::{BlockEncrypt, KeyInit};
        let key = [0u8; 32];
        let iv = [255u8; 16];
        let mut stream = new_aes_ctr(&key, &iv);
        let mut data = [0u8; 32];
        stream.xor(&mut data);
        let aes = aes::Aes256::new((&key).into());
        let mut block = [0u8; 16].into();
        aes.encrypt_block(&mut block);
        assert_eq!(&data[16..], block.as_slice());
    }
}
