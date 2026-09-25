package org.conscrypt;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/** A utility class for working with KeySpecs. */
public final class KeySpecUtil {
    private KeySpecUtil() {}

    /**
     * Creates a KeySpec object for the provided keySpecClass. The KeySpec must be a subclass of
     * EncodedKeySpec and its getFormat() method must return "raw".
     */
    public static <T extends KeySpec> T makeRawKeySpec(byte[] bytes, Class<T> keySpecClass)
            throws InvalidKeySpecException {
        try {
            Constructor<T> constructor = keySpecClass.getConstructor(byte[].class);
            T instance = constructor.newInstance((Object) bytes);
            EncodedKeySpec spec = (EncodedKeySpec) instance;
            if (!spec.getFormat().equalsIgnoreCase("raw")) {
                throw new InvalidKeySpecException("EncodedKeySpec class must be raw format");
            }
            return instance;
        } catch (NoSuchMethodException | InvocationTargetException | InstantiationException
                 | IllegalAccessException e) {
            throw new InvalidKeySpecException(
                    "Can't process KeySpec class " + keySpecClass.getName(), e);
        }
    }
}