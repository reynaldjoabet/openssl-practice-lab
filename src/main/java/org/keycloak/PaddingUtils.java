package org.keycloak;


public class PaddingUtils {

    private static final char PADDING_CHAR_NONE = '\u0000';

    /**
     * Applies padding to given string up to specified number of characters. If given string is shorter or same as maxPaddingLength, it will just return the original string.
     * Otherwise it would be padded with "\0" character to have at least "maxPaddingLength" characters
     *
     * @param rawString raw string
     * @param maxPaddingLength max padding length
     * @return padded output
     */
    public static String padding(String rawString, int maxPaddingLength) {
        if (rawString.length() < maxPaddingLength) {
            int nPad = maxPaddingLength - rawString.length();
            StringBuilder result = new StringBuilder(rawString);
            for (int i = 0 ; i < nPad; i++) result.append(PADDING_CHAR_NONE);
            return result.toString();
        } else
            return rawString;
    }
}
