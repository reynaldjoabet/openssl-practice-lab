package org.conscrypt;

import java.io.IOException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;



/**
 * An enum containing all known named groups for use in TLS.
 *
 * The enum also contains the required properties of each group and the
 * required functions (e.g. encoding/decoding).
 */
enum NamedGroup {
    // Elliptic curves (RFC 8422)
    SECP256_R1(0x0017, "secp256r1", "EC", new ECGenParameterSpec("secp256r1")),
    SECP384_R1(0x0018, "secp384r1", "EC", new ECGenParameterSpec("secp384r1")),
    SECP521_R1(0x0019, "secp521r1", "EC", new ECGenParameterSpec("secp521r1")),

    // Montgomery curves (RFC 8446)
    X25519(0x001D, "x25519", "XDH", NamedParameterSpec.X25519),
    X448(0x001E, "x448", "XDH", NamedParameterSpec.X448);

    final int id;               // hash + signature
    final String name;          // literal name
    // final NamedGroupSpec spec;  // group type
    // final ProtocolVersion[] supportedProtocols;
    final String algorithm;     // key exchange algorithm
    final AlgorithmParameterSpec keAlgParamSpec;
    final AlgorithmParameters keAlgParams;
    final boolean isAvailable;

    // performance optimization
    private static final Set<CryptoPrimitive> KEY_AGREEMENT_PRIMITIVE_SET =
        Collections.unmodifiableSet(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT));

    NamedGroup(int id, String name, String algorithm,
            AlgorithmParameterSpec keAlgParamSpec) {
        this.id = id;
        this.name = name;
        this.algorithm = algorithm;
        this.keAlgParamSpec = keAlgParamSpec;

        AlgorithmParameters params = null;
        boolean available = true;
        try {
            if (keAlgParamSpec instanceof ECGenParameterSpec) {
                params = AlgorithmParameters.getInstance(algorithm);
                params.init(keAlgParamSpec);
            } else {
                KeyAgreement.getInstance(algorithm);
            }
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
            available = false;
        }

        this.keAlgParams = params;
        this.isAvailable = available;
    }



    //
    // The next set of methods search & retrieve NamedGroups.
    //
    static NamedGroup valueOf(int id) {
        for (NamedGroup group : NamedGroup.values()) {
            if (group.id == id) {
                return group;
            }
        }

        return null;
    }


    static NamedGroup nameOf(String name) {
        for (NamedGroup group : NamedGroup.values()) {
            if (group.name.equalsIgnoreCase(name)) {
                return group;
            }
        }

        return null;
    }

    static String nameOf(int id) {
        for (NamedGroup group : NamedGroup.values()) {
            if (group.id == id) {
                return group.name;
            }
        }

        return "UNDEFINED-NAMED-GROUP(" + id + ")";
    }

    public static List<NamedGroup> namesOf(String[] namedGroups) {
        if (namedGroups == null) {
            return null;
        }

        if (namedGroups.length == 0) {
            return List.of();
        }

        List<NamedGroup> ngs = new ArrayList<>(namedGroups.length);
        for (String ss : namedGroups) {
            NamedGroup ng = NamedGroup.nameOf(ss);
            if (ng == null || !ng.isAvailable) {
                if (SSLLogger.isOn &&
                        SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest(
                            "Ignore the named group (" + ss
                                    + "), unsupported or unavailable");
                }

                continue;
            }

            ngs.add(ng);
        }

        return Collections.unmodifiableList(ngs);
    }


    static final class SupportedGroups {
        // the supported named groups, non-null immutable list
        static final String[] namedGroups;

        static {
            // The value of the System Property defines a list of enabled named
            // groups in preference order, separated with comma.  For example:
            //
            //      jdk.tls.namedGroups="secp521r1, secp256r1, ffdhe2048"
            //
            // If the System Property is not defined or the value is empty, the
            // default groups and preferences will be used.
            String property = System.getProperty("jdk.tls.namedGroups");
            if (property != null && !property.isEmpty()) {
                // remove double quote marks from beginning/end of the property
                if (property.length() > 1 && property.charAt(0) == '"' &&
                        property.charAt(property.length() - 1) == '"') {
                    property = property.substring(1, property.length() - 1);
                }
            }

            ArrayList<String> groupList;
            if (property != null && !property.isEmpty()) {
                String[] groups = property.split(",");
                groupList = new ArrayList<>(groups.length);
                for (String group : groups) {
                    group = group.trim();
                    if (!group.isEmpty()) {
                        NamedGroup namedGroup = nameOf(group);
                        if (namedGroup != null) {
                            if (namedGroup.isAvailable) {
                                groupList.add(namedGroup.name);
                            }
                        }   // ignore unknown groups
                    }
                }

                if (groupList.isEmpty()) {
                    throw new IllegalArgumentException(
                            "System property jdk.tls.namedGroups(" +
                            property + ") contains no supported named groups");
                }
            } else {        // default groups
                NamedGroup[] groups = new NamedGroup[] {
                        X25519,
                        SECP256_R1,
                        SECP384_R1,
                        SECP521_R1,
                        X448
                    };

                groupList = new ArrayList<>(groups.length);
                for (NamedGroup group : groups) {
                    if (group.isAvailable) {
                        groupList.add(group.name);
                    }
                }

                if (groupList.isEmpty() &&
                        SSLLogger.isOn && SSLLogger.isOn("ssl")) {
                    SSLLogger.warning("No default named groups");
                }
            }

            namedGroups = groupList.toArray(new String[0]);
        }
    }
}
