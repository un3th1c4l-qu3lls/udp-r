//! UDPv's

//! RFC 1071 checksum.
pub fn checksum(words: &[u16]) -> u16 {
    let mut accumulator: u32 = 0;
    for word in words {
        accumulator += *word as u32; // word is a reference, ffs
    }
    while accumulator >> 16 != 0 {
        accumulator = (accumulator & 0xFFFF) + (accumulator >> 16);
    }
    !(accumulator as u16)
}

pub struct Checksum {
   pub accumulator: u32 
}

impl Checksum {
    pub fn new() -> Self {
        Self {accumulator: 0u32}
    }

    pub fn update_from_words(& mut self, words: &[u16]) -> Result<(), &'static str> {
        for word in words {
            self.accumulator += *word as u32;
        }
        Ok(())
    }

    pub fn update_from_bytes(& mut self, bytes: &[u8]) -> Result<(), &'static str> {
        if bytes.len() % 2 != 0 {
            return Err("`bytes` needs to be word aligned.");
        }
        for i in 0..bytes.len() / 2 {
            let word = u16::from_be_bytes(bytes[2 * i..2 * (i + 1)].try_into().unwrap());
            self.accumulator += word as u32;
        }
        Ok(())
    }

    pub fn digest(&self) -> u16 {
        let mut accumulator: u32 = self.accumulator;
        while accumulator >> 16 != 0 {
            accumulator = (accumulator & 0xffffu32) + (accumulator >> 16);
        }
        !(accumulator as u16)
    }
}

pub mod v4; // RFC 768
pub mod v6; // RFC 8200

pub const PROTOCOL_NO: u8 = 17;

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl Header {
    pub const PACKED_SIZE: usize = 8;
    pub fn from_bytes(raw: &[u8]) -> Result<Header, &'static str> {
        if raw.len() < Self::PACKED_SIZE {
            return Err("UDP `Header` expected at least 8 bytes (partial).");
        }
        Ok(Self {
            source_port: u16::from_be_bytes(raw[..2].try_into().unwrap()),
            destination_port: u16::from_be_bytes(raw[2..4].try_into().unwrap()),
            length: u16::from_be_bytes(raw[4..6].try_into().unwrap()),
            checksum: u16::from_be_bytes(raw[6..8].try_into().unwrap()),
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::<u8>::with_capacity(Self::PACKED_SIZE);
        out.extend_from_slice(&self.source_port.to_be_bytes());
        out.extend_from_slice(&self.destination_port.to_be_bytes());
        out.extend_from_slice(&self.length.to_be_bytes());
        out.extend_from_slice(&self.checksum.to_be_bytes());
        Ok(out)
    }
}

pub mod datagram {
    pub fn from_bytes(bytes: &[u8]) -> Result<(super::Header, &[u8]), &'static str> {
        //! Serializes a datagram, check `surplus` when needed.
        let header = super::Header::from_bytes(bytes)?;
        if bytes.len() < header.length as usize {
            return Err("UDP `datagram` only partial, missing data.");
        }
        Ok((
            header,
            &bytes[super::Header::PACKED_SIZE..header.length as usize],
        ))
    }

    pub fn to_bytes(tuple: (super::Header, &[u8])) -> Result<Vec<u8>, &'static str> {
        //! Deserializes a datagram, check `surplus` when needed.
        let mut out = Vec::<u8>::with_capacity(super::Header::PACKED_SIZE + tuple.1.len());
        out.extend_from_slice(&tuple.0.to_bytes()?);
        out.extend_from_slice(tuple.1);
        Ok(out)
    }
}

pub mod option {
    //! UDP Option - RFC 9868
    pub fn from_bytes(bytes: &[u8]) -> Result<(u8, &[u8]), &'static str> {
        if bytes.len() < 1 {
            return Err("`option` only partial, more data required.");
        }
        let kind = bytes[0];
        if kind == self::eol::KIND || kind == self::nop::KIND {
            return Ok((kind, &[]));
        } else if bytes.len() < 2 {
            return Err("`option` only partial, more data required.");
        }
        let mut length: u16 = bytes[1] as u16;
        let mut offset: usize = 2;
        if length == 0xff {
            if bytes.len() < 4 {
                return Err("`option` extended only partial, more data required.");
            }
            length = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
            offset = 4usize;
        }
        if bytes.len() < length as usize {
            return Err("`option` extended data only partial, more data required.");
        }
        Ok((kind, &bytes[offset..length as usize]))
    }

    pub fn to_bytes(tuple: (u8, &[u8])) -> Result<Vec<u8>, &'static str> {
        if tuple.1.len() > u16::MAX as usize - 4 {
            return Err("`option` data too big.");
        }
        let mut out = Vec::<u8>::with_capacity(2 + if tuple.1.len() > 0xfc {0x2} else {0x0} + tuple.1.len());
        out.push(tuple.0);
        out.push(if tuple.1.len() > 0xfc {0xff} else {tuple.1.len() as u8 + 2});
        if tuple.1.len() > 0xfc {
            out.extend_from_slice(&(4 + tuple.1.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(tuple.1);
        Ok(out)
    }

    pub mod eol {
        //! End of Options List
        pub const KIND: u8 = 0x0;
        pub fn from_option(tuple: (u8, &[u8])) -> Result<(), &'static str> {
            if tuple.0 != self::KIND {
                return Err("`eol` option kind mismatch.");
            } else if tuple.1.len() != 0 {
                return Err("`eol` option expected no data.");
            }
            Ok(())
        }

        pub fn to_option() -> Result<(u8, &'static [u8]), &'static str> {
            Ok((self::KIND, &[]))
        }
    }

    pub mod nop {
        //! No Operation
        pub const KIND: u8 = 0x1;
        pub fn from_option(tuple: (u8, &[u8])) -> Result<(), &'static str> {
            if tuple.0 != self::KIND {
                return Err("`nop` option kind mismatch.");
            } else if tuple.1.len() != 0 {
                return Err("`nop` option expected no data.");
            }
            Ok(())
        }

        pub fn to_option() -> Result<(u8, &'static [u8]), &'static str> {
            Ok((self::KIND, &[]))
        }
    }

    pub mod apc {
        //! Additional Payload Checksum
        pub const KIND: u8 = 0x2;
        pub fn from_option(tuple: (u8, &[u8])) -> Result<u32, &'static str> {
            if tuple.0 != self::KIND {
                return Err("`apc` option kind mismatch.");
            } else if tuple.1.len() != 4 {
                return Err("`apc` option data expected exactly 4 bytes.");
            }
            Ok(u32::from_be_bytes(tuple.1[..4].try_into().unwrap()))
        }

        pub fn to_option(checksum: u32) -> Result<(u8, Vec<u8>), &'static str> {
            let mut out = Vec::<u8>::with_capacity(0x4);
            out.extend_from_slice(&checksum.to_be_bytes());
            Ok((self::KIND, out))
        }
    }


    pub mod frag {
        //! Fragmentation
        pub const KIND: u8 = 0x3;
        pub fn from_option(tuple: (u8, &[u8])) -> Result<(u32, u32, u16), &'static str> {
            if tuple.0 != self::KIND {
                return Err("`frag` option kind mismatch.");
            } else if tuple.1.len() != 8 && tuple.1.len() != 10 {
                return Err("`frag` option data expected exactly 8 | 10 bytes.");
            }
            let identification;
            let mut offset = 0usize;
            if tuple.1.len() == 8 {
                identification = u16::from_be_bytes(tuple.1[..2].try_into().unwrap()) as u32;
            } else {
                identification = u32::from_be_bytes(tuple.1[..4].try_into().unwrap());
                offset = 2;
            }

            Ok((identification, u32::from_be_bytes(tuple.1[2 + offset..2 + offset + 4].try_into().unwrap()), u16::from_be_bytes(tuple.1[2 + offset + 4..2 + offset + 2].try_into().unwrap())))
        }

        pub fn to_option(tuple: (u32, u32, u16)) -> Result<(u8, Vec<u8>), &'static str> {
            let mut out = Vec::<u8>::with_capacity(8 + if tuple.0 > 0xffff {2} else {0});
            if tuple.0 > 0xffff {
                out.extend_from_slice(&tuple.0.to_be_bytes());
            } else {
                out.extend_from_slice(&(tuple.0 as u16).to_be_bytes());
            }
            out.extend_from_slice(&tuple.1.to_be_bytes());
            out.extend_from_slice(&tuple.2.to_be_bytes());
            Ok((self::KIND, out))
        }
    }


    pub mod mds {
        //! Maximum Datagram Size
        pub const KIND: u8 = 0x04;
        pub fn from_option(tuple: (u8, &[u8])) -> Result<u16, &'static str> {
            if tuple.0 != self::KIND {
                return Err("`option` kind mismatch.");
            } else if tuple.1.len() != 2 {
                return Err("`option` data expected exactly 2 bytes.");
            }
            Ok(u16::from_be_bytes(tuple.1[..2].try_into().unwrap()))
        }

        pub fn to_option(maximum: u16) -> Result<(u8, Vec<u8>), &'static str> {
            let mut out = Vec::<u8>::with_capacity(0x02);
            out.extend_from_slice(&maximum.to_be_bytes());
            Ok((self::KIND, out))
        }
    }

    pub mod mrds {
        //! Maximum Reassembled Datagram Size
        pub const KIND: u8 = 0x5;
        pub fn from_option(tuple: (u8, &[u8])) -> Result<(u16, u8), &'static str> {
            if tuple.0 != self::KIND {
                return Err("`option` kind mismatch.");
            } else if tuple.1.len() != 3 {
                return Err("`option` data expected exactly 3 bytes.");
            }
            Ok((u16::from_be_bytes(tuple.1[..2].try_into().unwrap()), tuple.1[2]))
        }

        pub fn to_option(tuple: (u16, u8)) -> Result<(u8, Vec<u8>), &'static str> {
            let mut out = Vec::<u8>::with_capacity(0x02);
            out.extend_from_slice(&tuple.0.to_be_bytes());
            out.push(tuple.1);
            Ok((self::KIND, out))
        }
    }


    pub mod req {
        //! Request
        pub const KIND: u8 = 0x06;
        pub fn from_option(tuple: (u8, &[u8])) -> Result<u32, &'static str> {
            if tuple.0 != self::KIND {
                return Err("`option` kind mismatch.");
            } else if tuple.1.len() != 4 {
                return Err("`option` data expected exactly 4 bytes.");
            }
            Ok(u32::from_be_bytes(tuple.1[..4].try_into().unwrap()))
        }

        pub fn to_option(sequence: u32) -> Result<(u8, Vec<u8>), &'static str> {
            let mut out = Vec::<u8>::with_capacity(0x04);
            out.extend_from_slice(&sequence.to_be_bytes());
            Ok((self::KIND, out))
        }
    }


    pub mod res {
        //! Response
        pub const KIND: u8 = 0x07;
        pub fn from_option(tuple: (u8, &[u8])) -> Result<u32, &'static str> {
            if tuple.0 != self::KIND {
                return Err("`option` kind mismatch.");
            } else if tuple.1.len() != 4 {
                return Err("`option` data expected exactly 4 bytes.");
            }
            Ok(u32::from_be_bytes(tuple.1[..4].try_into().unwrap()))
        }

        pub fn to_option(sequence: u32) -> Result<(u8, Vec<u8>), &'static str> {
            let mut out = Vec::<u8>::with_capacity(0x04);
            out.extend_from_slice(&sequence.to_be_bytes());
            Ok((self::KIND, out))
        }
    }


    pub mod time {
        //! Timestamp
        pub const KIND: u8 = 0x08;
        pub fn from_option(tuple: (u8, &[u8])) -> Result<u64, &'static str> {
            if tuple.0 != self::KIND {
                return Err("`option` kind mismatch.");
            } else if tuple.1.len() != 8 {
                return Err("`option` data expected exactly 8 bytes.");
            }
            Ok(u64::from_be_bytes(tuple.1[..8].try_into().unwrap()))
        }

        pub fn to_option(timestamp: u64) -> Result<(u8, Vec<u8>), &'static str> {
            let mut out = Vec::<u8>::with_capacity(0x8);
            out.extend_from_slice(&timestamp.to_be_bytes());
            Ok((self::KIND, out))
        }
    }

    pub mod auth {
        //! Authentication
        pub const KIND: u8 = 0x9;

    }

    pub mod exp {
        //! RFC 3692-style experiments
        pub const KIND: u8 = 0x7f;
    }

    pub mod ucmp {
        //! UNSAFE Compression
        pub const KIND: u8 = 192;

    }

    pub mod uenc {
        //! UNSAFE Encryption
        pub const KIND: u8 = 193;
    }

    pub mod uexp {
        //! RFC 3692-style UNSAFE experiments
        pub const KIND: u8 = 254;
    }
}


pub mod surplus {
    //! Surplus Area - RFC 9868
    pub fn from_bytes(bytes: &[u8]) -> Result<(u16, Vec<(u8, &[u8])>), &'static str> {
        //! User has to take care of the padding byte.
        if bytes.len() < 2 {
            return Err("`surplus` area incomplete, more data required.")
        }
        let ocs = u16::from_be_bytes(bytes[..2].try_into().unwrap());
        let mut data = &bytes[2..];
        let mut options = Vec::<(u8, &[u8])>::new();
        loop {
            let option = super::option::from_bytes(data)?;
            options.push(option);
            let olength: usize = 1 + if option.0 != super::option::eol::KIND && option.0 != super::option::nop::KIND {1} else {0} + option.1.len() + if option.1.len() > 0xfc {2} else {0};
            data = &data[olength..];
            if data.is_empty() && option.0 != super::option::eol::KIND {
                return Err("`eol` missing.");
            } else if option.0 == super::option::eol::KIND {
                break;
            }
        }
        Ok((ocs, options))
    }

    pub fn to_bytes(tuple: (u16, Vec<(u8, &[u8])>)) -> Result<Vec<u8>, &'static str> {
        let mut bytes = Vec::<u8>::with_capacity(2);
        bytes.extend_from_slice(&tuple.0.to_be_bytes());
        for option in tuple.1 {
            bytes.extend_from_slice(&super::option::to_bytes(option)?);
        }
        Ok(bytes)
    }

    pub fn make(mut options: Vec<(u8, &[u8])>, header: super::Header) -> Result<(u16, Vec<(u8, &[u8])>), &'static str> {
        // Ensure eol.
        if !options.iter().any(|option| option.0 == super::option::eol::KIND) {
            options.push(super::option::eol::to_option()?);
        }
        
        // Compute checksum;
        let mut bytes = Vec::<u8>::new();
        let mut cs = super::Checksum::new();
        if header.length & 0x1 == 0x1 {
            bytes.push(0);
        }
        bytes.extend_from_slice(&[0u8; 2]);
        for option in &options {
            bytes.extend_from_slice(&super::option::to_bytes(*option)?);
            cs.update_from_bytes(&bytes[..bytes.len() & !1])?;
            let len = bytes.len();
            bytes.copy_within(len & !1.., 0);
            bytes.truncate(len - (len & !1));

        }
        if bytes.len() & 0x1 == 0x1 {
            bytes.push(0);
        }
        cs.update_from_bytes(&bytes)?;
        bytes.clear();
        Ok((cs.digest(), options))
    }

    pub fn check(tuple: (u16, Vec<(u8, &[u8])>), header: super::Header) -> Result<bool, &'static str> {

        // Compute checksum;
        let mut bytes = Vec::<u8>::new();
        let mut cs = super::Checksum::new();
        if header.length & 0x1 == 0x1 {
            bytes.push(0);
        }
        bytes.extend_from_slice(&[0u8; 2]);
        for option in &tuple.1 {
            bytes.extend_from_slice(&super::option::to_bytes(*option)?);
            cs.update_from_bytes(&bytes[..bytes.len() & !1])?;
            let len = bytes.len();
            bytes.copy_within(len & !1.., 0);
            bytes.truncate(len - (len & !1));
        }
        if bytes.len() & 0x1 == 0x1 {
            bytes.push(0);
        }
        cs.update_from_bytes(&bytes)?;
        bytes.clear();

        Ok(tuple.0 == cs.digest())
    }
}



/*
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
*/
