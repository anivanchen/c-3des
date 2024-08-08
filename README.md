# c-3des

## Overview

DES (Data Encryption Standard) is a symmetric key algorithm that encrypts data in 64-bit blocks. It uses a 64-bit key to encrypt and decrypt data. The algorithm is based on a Feistel network, which is a symmetric style structure used in the construction of block ciphers. The algorithm consists of an initial permutation, 16 rounds of key-dependent computation, and a final permutation. The key-dependent computation involves splitting the data block into two 32-bit blocks, L and R, and applying a function F to R using a 48-bit key. The key schedule function generates the 16 round keys from the 64-bit key. The algorithm is designed to be secure against differential and linear cryptanalysis.

Triple DES (3DES) is a variant of DES that applies the DES algorithm three times to each data block. It uses three 64-bit keys, K1, K2, and K3, and encrypts the data block with K1, decrypts it with K2, and encrypts it again with K3. This provides a higher level of security than DES, but is approximately 3 times slower due to the increased number of rounds.

To generate each 64 bit key, an implementation of SHA-256 will be used. SHA-256 is a cryptographic hash function that generates a 256-bit hash value from an input message. It is designed to be secure against collision attacks and pre-image attacks. The algorithm consists of several rounds of message expansion, mixing, and compression, and uses a set of constant values and functions to generate the hash value. A truncated hash value is used as the key for this implementation of the DES algorithm. 3 portions of this 256-bit key is used for the 3DES algorithm.

This project aims to implement the 3DES algorithm with SHA-256 as the Key Derivation Function (KDF) in C. The implementation of 3DES was done in reference to the specifications in [FIPS PUB 46-3](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf). The implementation of SHA-256 was done in reference to the specifications in [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf). Note that 3DES is not recommended for new applications due to its slow speed and the availability of more secure algorithms such as AES. NIST has deprecated the use of 3DES for new applications and recommends the use of AES instead.

## Presentation

https://drive.google.com/file/d/1b2lm-mRY9qot24Ujqyq5Am1JA5PG2VgK/view?usp=sharing

## Instructions

To compile the program, run:

```bash
make compile
```

This program is able to encrypt and decrypt files using the DES algorithm, along with the 3DES variant. A passphrase file must be provided to encrypt or decrypt a file. 

To output a hash of a file to a file named `sha_output.txt`, run:

```bash
make sha input=<input filename>
```

To encrypt a file using DES, run:

```bash
make encrypt input=<input filename> output=<output filename> key=<key filename> triple=false
```

To encrypt a file using 3DES, run:

```bash
make encrypt input=<input filename> output=<output filename> key=<key filename> triple=true
```

To decrypt a file using DES, run:

```bash
make decrypt input=<input filename> output=<output filename> key=<key filename> triple=false
```

To decrypt a file using 3DES, run:

```bash
make decrypt input=<input filename> output=<output filename> key=<key filename> triple=true
```

To clean the compiled files, run:

```bash
make clean
```

To run tests on each part of the DES algorithm, run:

```bash
make test
```

## Research Notes

https://docs.google.com/document/d/1SLU-Vclc7APL3wPdBwLeB8y79mH-YCzmRIgBG8pXz-g/edit?usp=sharing

## Notes

This implementation is not recommended for use in production environments. The 3DES algorithm and SHA-256 algorithm are not optimized for speed or memory usage. The SHA-256 implementation is intended to provide a key derivation function for the 3DES algorithm. The 3DES implementation is intended for educational purposes and to demonstrate the workings of the symmetric encryption algorithm. 

