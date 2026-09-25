package org.conscrypt;


interface AESConstants {

    // AES block size in bytes.
    int AES_BLOCK_SIZE = 16;

    // Valid AES key sizes in bytes.
    // NOTE: The values need to be listed in an *increasing* order
    // since DHKeyAgreement depends on this fact.
    int[] AES_KEYSIZES = { 16, 24, 32 };
}
