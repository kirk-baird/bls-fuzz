pub const SCALAR_BYTES: usize = 48;
pub const G1_BYTES: usize = 48;
pub const G2_BYTES: usize = 96;

// This file provides wrapper functions where required for BLS libraries.
pub mod milagro {
    use super::*;

    use amcl::errors::AmclError;
    use amcl::bls381::ecp::ECP;
    use amcl::bls381::bls381::utils::deserialize_g1;

    pub fn decompress_g1(g1_bytes: &[u8]) -> Result<ECP, AmclError> {
        if g1_bytes.len() != G1_BYTES {
            return Err(AmclError::InvalidG1Size);
        }
        deserialize_g1(g1_bytes)
    }
}
