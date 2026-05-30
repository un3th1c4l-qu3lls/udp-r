//! UDPv6 - RFC 8200

#[derive(Clone, Copy, Debug)]
pub struct PseudoHeader {
    pub source_address: u128,
    pub destination_address: u128,
    pub ul_length: u32,
    pub next_header: u8
}

impl PseudoHeader {
    pub const PACKED_SIZE: usize = 40;
    pub fn from_bytes(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < Self::PACKED_SIZE {
            return Err("");
        }
        Ok(Self {
            source_address: u128::from_be_bytes(raw[..16].try_into().unwrap()),
            destination_address: u128::from_be_bytes(raw[16..32].try_into().unwrap()),
            ul_length: u32::from_be_bytes(raw[32..36].try_into().unwrap()),
            next_header: raw[39]
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::<u8>::with_capacity(Self::PACKED_SIZE);
        out.extend_from_slice(&self.source_address.to_be_bytes());
        out.extend_from_slice(&self.destination_address.to_be_bytes());
        out.extend_from_slice(&(((self.ul_length as u64) << 32) | (self.next_header as u64)).to_be_bytes());
        Ok(out)
    }
}

pub mod datagram {
    //! UDPv6 datagram.
    //! Be aware that null value checksums should be invalid, although tunnel exemptions may apply (RFC 6935/6936).
    pub fn make(
        tuple: &mut (super::PseudoHeader, super::super::Header, &[u8]),
    ) -> Result<(), &'static str> {
        //! Make a valid datagram : source / destination ports / addresses, protocol left untouched.
        //! Checksum, lengths modified.
        /*

        payload limit is u16::MAX - super::super::Header::PACKED_SIZE or u32::MAX - super::super::Header::PACKED_SIZE

        */
        if tuple.2.len() > u32::MAX as usize - super::super::Header::PACKED_SIZE {
            return Err("UDP data does not fit.");
        }
        let length: u32 = (super::super::Header::PACKED_SIZE + tuple.2.len()) as u32;
        tuple.1.length = if length > u16::MAX as u32 {0x0} else {length as u16};
        tuple.0.ul_length = length;
        if tuple.1.checksum != 0 {
            tuple.1.checksum = 0;

            let mut cs = super::super::Checksum::new();
            cs.update_from_bytes(&tuple.0.to_bytes()?)?;
            cs.update_from_bytes(&tuple.1.to_bytes()?)?;
            let data = &tuple.2[..tuple.2.len() & !1];
            cs.update_from_bytes(data)?;
            if tuple.2.len() % 2 != 0 {
                let padded = [tuple.2[tuple.2.len() - 1], 0u8];
                cs.update_from_bytes(&padded)?;
            }
            tuple.1.checksum = cs.digest();

            if tuple.1.checksum == 0 {
                tuple.1.checksum = !tuple.1.checksum; // 0xffff
            }
        }
        Ok(())
    }

    pub fn check(
        tuple: &mut (super::PseudoHeader, super::super::Header, &[u8]),
    ) -> Result<bool, &'static str> {
        //! Check datagram for validity (lengths, protocol, checksum).
        // Sanity checks
        if tuple.0.next_header != super::super::PROTOCOL_NO {
            return Err("`PseudoHeader`'s protocol field expected 17 (UDP).");
        } else if tuple.2.len() > u32::MAX as usize - super::super::Header::PACKED_SIZE {
            return Err("UDP data does not fit.");
        }
        let length: u32 = (super::super::Header::PACKED_SIZE + tuple.2.len()) as u32;
        if tuple.0.ul_length != length || tuple.1.length != if length > u16::MAX as u32 {0x0} else {length as u16} {
            return Err("`datagram` length mismatches.");
        }
        // Checksum
        if tuple.1.checksum != 0 {
            let mut checksum: u16 = tuple.1.checksum;
            tuple.1.checksum = 0;

            let mut cs = super::super::Checksum::new();
            cs.update_from_bytes(&tuple.0.to_bytes()?)?;
            cs.update_from_bytes(&tuple.1.to_bytes()?)?;
            let data = &tuple.2[..tuple.2.len() & !1];
            cs.update_from_bytes(data)?;
            if tuple.2.len() % 2 != 0 {
                let padded = [tuple.2[tuple.2.len() - 1], 0u8];
                cs.update_from_bytes(&padded)?;
            }
            tuple.1.checksum = checksum;
            checksum = cs.digest();
            if checksum == 0 {
                checksum = !checksum;
            }
            return Ok(tuple.1.checksum == checksum);
        }
        Ok(true)
    }
}