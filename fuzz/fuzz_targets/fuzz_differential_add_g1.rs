#![no_main]
use libfuzzer_sys::fuzz_target;
use milagro_bls::{AggregatePublicKey as MilagroAggregatePublicKey, PublicKey as MilagroPublicKey};
use blst::min_pk::{AggregatePublicKey as BlstAggregatePublicKey, PublicKey as BlstPublicKey};
use bls12_381::{G1Affine, G1Projective};
use core::ops::Add;

// Tests a + b = c for all implementations against milagro bls
fuzz_target!(|data: &[u8]| {
    if data.len() != 96 { return; }
    let a = &data[0..48];
    let b = &data[48..];

    if let Ok(milagro_a) = MilagroPublicKey::from_bytes(a) {
        if let Ok(milagro_b) = MilagroPublicKey::from_bytes(b) {
            // Milagro
            let mut milagro_c = MilagroAggregatePublicKey::from_public_key(&milagro_a);
            milagro_c.add(&milagro_b);
            let c_bytes = milagro_c.as_bytes().to_vec();

            // BLST
            let mut blst_a = BlstAggregatePublicKey::from_public_key(&BlstPublicKey::uncompress(a).unwrap());
            let blst_b = BlstPublicKey::uncompress(b).unwrap();
            blst_a.add_public_key(&blst_b);
            assert_eq!(c_bytes, BlstPublicKey::from_aggregate(&blst_a).compress().to_vec());


            // ZK-crypto
            let mut data_array = [0u8; 48];
            data_array.copy_from_slice(a);
            let mut zkcrypto_a: G1Projective = G1Affine::from_compressed_unchecked(&data_array).unwrap().into();
            data_array.copy_from_slice(b);
            let zkcrypto_b: G1Projective = G1Affine::from_compressed_unchecked(&data_array).unwrap().into();
            let zkcrypto_c: G1Affine = zkcrypto_a.add(&zkcrypto_b).into();
            assert_eq!(c_bytes, zkcrypto_c.to_compressed().to_vec());
        }
    }
});
