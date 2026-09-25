package org.conscrypt;

    /**
     * The hash algorithms used for PRF (PseudoRandom Function) or HKDF.
     *
     * Note that TLS 1.1- uses a single MD5/SHA1-based PRF algorithm for
     * generating the necessary material.
     */
    enum HashAlg {
        H_NONE      ("NONE",    0,    0),
        H_SHA256    ("SHA-256", 32,  64),
        H_SHA384    ("SHA-384", 48, 128);

        final String name;
        final int hashLength;
        final int blockSize;
        final String hkdfAlgorithm;

        HashAlg(String hashAlg, int hashLength, int blockSize) {
            this.name = hashAlg;
            this.hashLength = hashLength;
            this.blockSize = blockSize;
            this.hkdfAlgorithm = "HKDF-" + hashAlg.replace("-", "");
        }

        @Override
        public String toString() {
            return name;
        }
    }