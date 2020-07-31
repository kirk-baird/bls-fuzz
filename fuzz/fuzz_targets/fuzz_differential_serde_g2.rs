#![no_main]
use libfuzzer_sys::fuzz_target;
use milagro_bls::Signature as MilagroSignature;
use blst::min_pk::Signature as BlstSignature;
use bls12_381::G2Affine;

fuzz_target!(|data: &[u8]| {
    // TODO: Known BLST Issue (0, +-2) is counted as infinity
    if data.len() > 0 && (data[0] == 128 || data[0] == 160) { return; }

    // TODO: Do milagro first as BLST currently has know injectiveness issues
    // and ZK-crypto requires valid bytes.
    if let Ok(milagro_g2) = MilagroSignature::from_bytes(data) {
        // BLST
        let blst_g2 = BlstSignature::uncompress(data).unwrap();

        // ZK-crypto
        let mut data_array = [0u8; 96];
        data_array.copy_from_slice(data);
        let zkcrypto_g2 = G2Affine::from_compressed_unchecked(&data_array).unwrap();

        let data_round_trip = milagro_g2.as_bytes().to_vec();
        assert_eq!(data_round_trip, blst_g2.compress().to_vec());
        assert_eq!(data_round_trip, zkcrypto_g2.to_compressed().to_vec());
    }
});
