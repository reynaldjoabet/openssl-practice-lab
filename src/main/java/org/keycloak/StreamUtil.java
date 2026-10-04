package org.keycloak;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;


public final class StreamUtil {

    private static final int BUFFER_LENGTH = 4096;

    private StreamUtil() {
    }

    /**
     * Reads string from byte input stream.
     * @param in InputStream to build the String from
     * @return String representation of the input stream contents decoded using default charset
     * @throws IOException
     * @deprecated Use {@link #readString(java.io.InputStream, java.nio.charset.Charset)} variant.
     */
    @Deprecated
    public static String readString(InputStream in) throws IOException
    {
        return readString(in, Charset.defaultCharset());
    }

    /**
     * Reads string from byte input stream.
     * @param in InputStream to build the String from
     * @param charset Charset used to decode the input stream
     * @return String representation of the input stream contents decoded using given charset
     * @throws IOException
     */
    public static String readString(InputStream in, Charset charset) throws IOException
    {
        char[] buffer = new char[BUFFER_LENGTH];
        StringBuilder builder = new StringBuilder();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in, charset));
        int wasRead;
        do
        {
            wasRead = reader.read(buffer, 0, BUFFER_LENGTH);
            if (wasRead > 0)
            {
                builder.append(buffer, 0, wasRead);
            }
        }
        while (wasRead > -1);

        return builder.toString();
    }
}
