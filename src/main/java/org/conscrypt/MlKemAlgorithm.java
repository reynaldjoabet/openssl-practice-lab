package org.conscrypt;


/** ML-KEM algorithm. */
public enum MlKemAlgorithm {
    // Values from https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf, table 3.
    ML_KEM_768("ML-KEM-768", 1184),
    ML_KEM_1024("ML-KEM-1024", 1568);

    private final String name;
    private final int publicKeySize;

    private MlKemAlgorithm(String name, int publicKeySize) {
        this.name = name;
        this.publicKeySize = publicKeySize;
    }

    @Override
    public String toString() {
        return name;
    }

    public int publicKeySize() {
        return publicKeySize;
    }
}