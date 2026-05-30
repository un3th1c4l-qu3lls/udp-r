//! UDPv4 - RFC 768

#[derive(Clone, Copy, Debug)]
pub struct PseudoHeader {
    pub source_address: u32,
    pub destination_address: u32,
    pub protocol: u8,
    pub udp_length: u16,
}

impl PseudoHeader {
    pub const PACKED_SIZE: usize = 12;
    pub fn from_bytes(raw: &[u8]) -> Result<PseudoHeader, &'static str> {
        if raw.len() < Self::PACKED_SIZE {
            return Err("UDP `PseudoHeader` expected at least 12 bytes (partial).");
        }
        Ok(Self {
            source_address: u32::from_be_bytes(raw[..4].try_into().unwrap()),
            destination_address: u32::from_be_bytes(raw[4..8].try_into().unwrap()),
            protocol: raw[9],
            udp_length: u16::from_be_bytes(raw[10..12].try_into().unwrap()),
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::<u8>::with_capacity(Self::PACKED_SIZE);
        out.extend_from_slice(&self.source_address.to_be_bytes());
        out.extend_from_slice(&self.destination_address.to_be_bytes());
        out.extend_from_slice(&(self.protocol as u16).to_be_bytes());
        out.extend_from_slice(&(self.udp_length).to_be_bytes());
        Ok(out)
    }
}


pub mod datagram {
    //! UDPv4 datagram.
    pub fn make(
        tuple: &mut (super::PseudoHeader, super::super::Header, &[u8]),
    ) -> Result<(), &'static str> {
        //! Make a valid datagram : source / destination ports / addresses, protocol left untouched.
        //! Checksum, lengths modified.
        if tuple.2.len() > u16::MAX as usize - super::super::Header::PACKED_SIZE {
            return Err("UDP data does not fit.");
        }
        let length: u16 = (super::super::Header::PACKED_SIZE + tuple.2.len()) as u16;
        tuple.1.length = length;
        tuple.0.udp_length = tuple.1.length;
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
        if tuple.0.protocol != super::super::PROTOCOL_NO {
            return Err("`PseudoHeader`'s protocol field expected 17 (UDP).");
        } else if tuple.2.len() > u16::MAX as usize - super::super::Header::PACKED_SIZE {
            return Err("UDP data does not fit.");
        }
        let length: u16 = (super::super::Header::PACKED_SIZE + tuple.2.len()) as u16;
        if tuple.0.udp_length != length || tuple.1.length != length {
            return Err("`datagram` length fields mismatches.");
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