#![no_main]
use libfuzzer_sys::fuzz_target;
use milagro_bls::PublicKey as MilagroPublicKey;
use blst::min_pk::PublicKey as BlstPublicKey;
use bls12_381::G1Affine;

fuzz_target!(|data: &[u8]| {
    // TODO: Known BLST Issue (0, +-2) is counted as infinity
    if data.len() > 0 && (data[0] == 128 || data[0] == 160) { return; }

    // TODO: Do milagro first as BLST currently has know injectiveness issues
    // and ZK-crypto requires valid bytes.
    if let Ok(milagro_g1) = MilagroPublicKey::from_bytes(data) {
        // BLST
        let blst_g1 = BlstPublicKey::uncompress(data).unwrap();

        // ZK-crypto
        let mut data_array = [0u8; 48];
        data_array.copy_from_slice(data);
        let zkcrypto_g1 = G1Affine::from_compressed_unchecked(&data_array).unwrap();

        let data_round_trip = milagro_g1.as_bytes().to_vec();
        assert_eq!(data_round_trip, blst_g1.compress().to_vec());
        assert_eq!(data_round_trip, zkcrypto_g1.to_compressed().to_vec());
    }
});
