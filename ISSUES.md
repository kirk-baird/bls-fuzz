# Issues Found

A list of issues that have been found, includes false positives and notes.

- milagro_bls `AggregatePublicKey` will successfully deserialise [0; 48] as empty.
- blst does not enforce field elements less than the field modulus.
- blst does not check compressed points byte length are exact (can be twice required length).
- blst converts the point (0, +-2) to the point at infinity in `uncompress()`
- zkcrypto does not check validity of sqaure root in `from_compressed()`.
