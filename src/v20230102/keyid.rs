use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::hash::Hash;

lazy_static! {
   static ref KMS_ARN_PARSE_PARTS_RE: Regex = Regex::new(r"arn:aws:kms:(?P<region>(?:us|eu)-(?:east|west)-[0-9]):(?P<account>[0-9]{12}):key/((?P<time_low>[a-fA-F0-9]{8})-(?P<time_mid>[a-fA-F0-9]{4})-(?P<time_high_and_version>4[a-fA-F0-9]{3})-(?P<clock_seq_and_reserved>[abAB89][a-fA-F0-9]{3})-(?P<node>[a-fA-F0-9]{12})|mrk-(?P<mrk>[a-fA-F0-9]{32}))").unwrap();
}

pub fn decode_hex_into <'a, 'b> (src: &'a str, src_off: usize, src_len: usize, dst: &'b mut [u8], dst_off: usize) -> Result<(), String> {
    if src_off % 2 != 0 {
        return Err("src offset is not an even number".to_string())
    }
    if src_len % 2 != 0 {
        return Err("src read length is not an even number".to_string())
    }
    if src_off + src_len > src.len() {
        return Err("src offset + src read length exceeds the lenth of src".to_string())
    }
    let mut src_idx = src_off;
    let mut dst_idx = dst_off;
    while src_idx < src_len {
        let byte = u8::from_str_radix(&src[src_idx..src_idx+2], 16).map_err(|e| e.to_string())?;
        dst[dst_idx] = byte;
        src_idx = src_idx + 2;
        dst_idx = dst_idx + 1;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KmsKeyType {
    Cmk,
    Mrk,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId {
    key_type: KmsKeyType,
    bytes: [u8;16],
}

impl KeyId {
    pub fn to_bytes <'me> (&'me self) -> Vec<u8> {
        let mut accum: Vec<u8> = vec![0; 17];
        accum[0] = if self.key_type == KmsKeyType::Cmk { 0x01} else { 0x02 };
        accum[1..].clone_from_slice(&self.bytes[..]);
        accum
    }
}

impl <'arn> TryFrom<&'arn String> for KeyId {
    type Error = String;

    fn try_from (arn: &'arn String) -> Result<Self, Self::Error> {
        KeyId::try_from(<String as AsRef<str>>::as_ref(arn))
    }
}


impl <'arn> TryFrom<&'arn str> for KeyId {
    type Error = String;

    fn try_from (arn: &'arn str) -> Result<Self, Self::Error> {
        let cap = KMS_ARN_PARSE_PARTS_RE
            .captures(arn)
            .ok_or("didnt match a AWS KMS CMK ARN".to_string())?;
        match (cap.name("mrk"), cap.name("time_low"), cap.name("time_mid"), cap.name("time_high_and_version"), cap.name("clock_seq_and_reserved"), cap.name("node")) {
            (Some(mrk), None, None, None, None, None) => {
                let mut bytes = [0u8;16];
                decode_hex_into(mrk.as_str(), 0, 32, &mut bytes, 0)?;
                Ok(KeyId{key_type: KmsKeyType::Mrk, bytes})
            },
            (None, Some(tl), Some(tm), Some(th), Some(seq), Some(node)) => {
                let mut bytes = [0u8;16];
                decode_hex_into(tl.as_str(), 0, 8, &mut bytes, 0)?;
                decode_hex_into(tm.as_str(), 0, 4, &mut bytes, 4)?;
                decode_hex_into(th.as_str(), 0, 4, &mut bytes, 6)?;
                decode_hex_into(seq.as_str(), 0, 4, &mut bytes, 8)?;
                decode_hex_into(node.as_str(), 0, 12, &mut bytes, 10)?;
                Ok(KeyId{key_type: KmsKeyType::Cmk, bytes})
            }
            _ => Err("Invalid Match".to_string())
        }

    }
}

impl <'bytes> TryFrom<&'bytes [u8]> for KeyId {
    type Error = String;
    
    fn try_from (b: &'bytes [u8]) -> Result<Self, Self::Error> {
        if b.len() != 17 {
            return Err(format!("Expected 17 bytes, received {}", b.len()))
        }
        let key_type = match b[0] {
            0x01 => Ok(KmsKeyType::Cmk),
            0x02 => Ok(KmsKeyType::Mrk),
            _ => Err(format!("Expected bytes[0] to be 0x01 or 0x02 byte value denoting the AWS KMS Key Type, found 0x{:02x}", b[0]))
        }?;

        let mut bytes = [0u8; 16];
        bytes[..].clone_from_slice(&b[1..]);
        Ok(KeyId { key_type, bytes })
    }
}

impl core::fmt::Display for KeyId {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self.key_type {
            KmsKeyType::Cmk => write!(f, "{:02x?}{:02x?}{:02x?}{:02x?}-{:02x?}{:02x?}-{:02x?}{:02x?}-{:02x?}{:02x?}-{:02x?}{:02x?}{:02x?}{:02x?}{:02x?}{:02x?}",
                &self.bytes[0], &self.bytes[1], &self.bytes[2],  &self.bytes[3],  &self.bytes[4],  &self.bytes[5],  &self.bytes[6],  &self.bytes[7],
                &self.bytes[8], &self.bytes[9], &self.bytes[10], &self.bytes[11], &self.bytes[12], &self.bytes[13], &self.bytes[14], &self.bytes[15],
            ),
            KmsKeyType::Mrk => write!(f, "mrk-{:02x?}{:02x?}{:02x?}{:02x?}{:02x?}{:02x?}{:02x?}{:02x?}{:02x?}{:02x?}{:02x?}{:02x?}{:02x?}{:02x?}{:02x?}{:02x?}",
                &self.bytes[0], &self.bytes[1], &self.bytes[2],  &self.bytes[3],  &self.bytes[4],  &self.bytes[5],  &self.bytes[6],  &self.bytes[7],
                &self.bytes[8], &self.bytes[9], &self.bytes[10], &self.bytes[11], &self.bytes[12], &self.bytes[13], &self.bytes[14], &self.bytes[15],
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyIndex {
    index: HashMap<KeyId, String>
}

impl KeyIndex {
    pub fn contains_arn <'arn, 'me> (&'me self, arn: &'arn str) -> bool {
        match KeyId::try_from(arn) {
            Err(_) => false,
            Ok(kid) => self.contains_kid(&kid),
        }
    }

    pub fn contains_kid <'kid, 'me> (&'me self, kid: &'kid KeyId) -> bool {
        self.index.contains_key(kid)
    }

    pub fn len <'me> (&'me self) -> usize {
        self.index.len()
    }
}

impl From<Vec<String>> for KeyIndex {
    fn from (arns: Vec<String>) -> Self {
        arns.iter().collect::<KeyIndex>()
    }
}

impl <'a> FromIterator<&'a String> for KeyIndex {
    fn from_iter<I: IntoIterator<Item=&'a String>>(iter: I) -> Self {
        let mut tpls: Vec<(KeyId, String)> = Vec::new();
        for arn in iter {
            let kid = KeyId::try_from(arn); 
            if kid.is_ok() {
                tpls.push((kid.unwrap(), arn.clone()));
            }
        }
        KeyIndex{ index: HashMap:: from_iter(tpls) }
    }
}

#[cfg(test)]
mod tests {
    use crate::{ KeyId, KeyIndex };
    const CMK_ARN: &'static str = "arn:aws:kms:us-west-2:230966178829:key/93c1b1e7-0f88-42f4-a009-cd4041eb87f3";
    const CMK_BYTES: &'static [u8] = b"\x01\x93\xc1\xb1\xe7\x0f\x88\x42\xf4\xa0\x09\xcd\x40\x41\xeb\x87\xf3";
    const MRK_ARN: &'static str = "arn:aws:kms:us-east-1:230966178829:key/mrk-5c8c05b2333b436092919ba60a1098bc";
    const MRK_BYTES: &'static [u8] = b"\x02\x5c\x8c\x05\xb2\x33\x3b\x43\x60\x92\x91\x9b\xa6\x0a\x10\x98\xbc";

    #[test]
    fn cmk_key_id_parsing_success () {
        let res = KeyId::try_from(CMK_ARN);
        assert!(res.is_ok());
        let cmk_deser = KeyId::try_from(CMK_BYTES);
        assert_eq!(cmk_deser, res); 
        assert_eq!(cmk_deser.unwrap().to_bytes(), Vec::from(CMK_BYTES));
    }
    #[test]
    fn cmk_key_id_parsing_fail () {
        let res = KeyId::try_from("");
        assert!(res.is_err());
    }
    #[test]
    fn mrk_key_id_parsing_success () {
        let res = KeyId::try_from(MRK_ARN);
        assert!(res.is_ok());
        let mrk_deser = KeyId::try_from(MRK_BYTES);
        assert_eq!(mrk_deser, res); 
        assert_eq!(mrk_deser.unwrap().to_bytes(), Vec::from(MRK_BYTES));
    }
    #[test]
    fn key_index_from_arns_vec () {
        let arns:Vec<String> = vec!(CMK_ARN.into(), MRK_ARN.into());
        let cmk_cache = KeyIndex::from(arns);
        assert_eq!(cmk_cache.len(), 2);
        assert!(cmk_cache.contains_arn(CMK_ARN));
        assert!(cmk_cache.contains_arn(MRK_ARN));
    }
}

