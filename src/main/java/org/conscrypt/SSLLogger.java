package org.conscrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Implementation of SSL logger.
 *
 * If the system property "javax.net.debug" is not defined, the debug logging
 * is turned off.  If the system property "javax.net.debug" is defined as
 * empty, the debug logger is specified by System.getLogger("javax.net.ssl"),
 * and applications can customize and configure the logger or use external
 * logging mechanisms.  If the system property "javax.net.debug" is defined
 * and non-empty, a private debug logger implemented in this class is used.
 */
public final class SSLLogger {
    private static final System.Logger logger;
    private static final String property;
    public static final boolean isOn;

    static {
        String p = System.getProperty("javax.net.debug");
        if (p != null) {
            if (p.isEmpty()) {
                property = "";
                logger = System.getLogger("javax.net.ssl");
            } else {
                property = p.toLowerCase(Locale.ENGLISH);
                if (property.equals("help")) {
                    help();
                }

                logger = new SSLConsoleLogger("javax.net.ssl", p);
            }
            isOn = true;
        } else {
            property = null;
            logger = null;
            isOn = false;
        }
    }

    private static void help() {
        System.err.println();
        System.err.println("help           print the help messages");
        System.err.println("expand         expand debugging information");
        System.err.println();
        System.err.println("all            turn on all debugging");
        System.err.println("ssl            turn on ssl debugging");
        System.err.println();
        System.err.println("The following can be used with ssl:");
        System.err.println("\trecord       enable per-record tracing");
        System.err.println("\thandshake    print each handshake message");
        System.err.println("\tkeygen       print key generation data");
        System.err.println("\tsession      print session activity");
        System.err.println("\tdefaultctx   print default SSL initialization");
        System.err.println("\tsslctx       print SSLContext tracing");
        System.err.println("\tsessioncache print session cache tracing");
        System.err.println("\tkeymanager   print key manager tracing");
        System.err.println("\ttrustmanager print trust manager tracing");
        System.err.println("\tpluggability print pluggability tracing");
        System.err.println();
        System.err.println("\thandshake debugging can be widened with:");
        System.err.println("\tdata         hex dump of each handshake message");
        System.err.println("\tverbose      verbose handshake message printing");
        System.err.println();
        System.err.println("\trecord debugging can be widened with:");
        System.err.println("\tplaintext    hex dump of record plaintext");
        System.err.println("\tpacket       print raw SSL/TLS packets");
        System.err.println();
        System.exit(0);
    }

    /**
     * Return true if the "javax.net.debug" property contains the
     * debug check points, or System.Logger is used.
     */
    public static boolean isOn(String checkPoints) {
        if (property == null) {              // debugging is turned off
            return false;
        } else if (property.isEmpty()) {     // use System.Logger
            return true;
        }                                   // use provider logger

        String[] options = checkPoints.split(",");
        for (String option : options) {
            option = option.trim();
            if (!SSLLogger.hasOption(option)) {
                return false;
            }
        }

        return true;
    }

    private static boolean hasOption(String option) {
        option = option.toLowerCase(Locale.ENGLISH);
        if (property.contains("all")) {
            return true;
        } else {
            // remove first occurrence of "sslctx" since
            // it interferes with search for "ssl"
            String modified = property.replaceFirst("sslctx", "");
            if (modified.contains("ssl")) {
                // don't enable data and plaintext options by default
                if (!(option.equals("data")
                        || option.equals("packet")
                        || option.equals("plaintext"))) {
                    return true;
                }
            }
        }

        return property.contains(option);
    }

    public static void severe(String msg, Object... params) {
        SSLLogger.log(Level.ERROR, msg, params);
    }

    public static void warning(String msg, Object... params) {
        SSLLogger.log(Level.WARNING, msg, params);
    }

    public static void info(String msg, Object... params) {
        SSLLogger.log(Level.INFO, msg, params);
    }

    public static void fine(String msg, Object... params) {
        SSLLogger.log(Level.DEBUG, msg, params);
    }

    public static void finer(String msg, Object... params) {
        SSLLogger.log(Level.TRACE, msg, params);
    }

    public static void finest(String msg, Object... params) {
        SSLLogger.log(Level.ALL, msg, params);
    }

    private static void log(Level level, String msg, Object... params) {
        if (logger != null && logger.isLoggable(level)) {
            if (params == null || params.length == 0) {
                logger.log(level, msg);
            } else {
                try {
                    logger.log(level, msg);
                } catch (Exception exp) {
                    // ignore it, just for debugging.
                }
            }
        }
    }



    // Logs a warning message and always returns false. This method
    // can be used as an OR Predicate to add a log in a stream filter.
    public static boolean logWarning(String option, String s) {
        if (SSLLogger.isOn && SSLLogger.isOn(option)) {
            SSLLogger.warning(s);
        }
        return false;
    }

    private static class SSLConsoleLogger implements Logger {
        private final String loggerName;
        private final boolean useCompactFormat;

        SSLConsoleLogger(String loggerName, String options) {
            this.loggerName = loggerName;
            options = options.toLowerCase(Locale.ENGLISH);
            this.useCompactFormat = !options.contains("expand");
        }

        @Override
        public String getName() {
            return loggerName;
        }

        @Override
        public boolean isLoggable(Level level) {
            return level != Level.OFF;
        }

        @Override
        public void log(Level level,
                ResourceBundle rb, String message, Throwable thrwbl) {
            if (isLoggable(level)) {
                try {
                
                } catch (Exception exp) {
                    // ignore it, just for debugging.
                }
            }
        }

        @Override
        public void log(Level level,
                ResourceBundle rb, String message, Object... params) {
            if (isLoggable(level)) {
                try {
            
                } catch (Exception exp) {
                    // ignore it, just for debugging.
                }
            }
        }
    }

    private static class SSLSimpleFormatter {
        private static final String PATTERN = "yyyy-MM-dd kk:mm:ss.SSS z";
        private static final DateTimeFormatter dateTimeFormat = DateTimeFormatter.ofPattern(PATTERN, Locale.ENGLISH)
                                                                                 .withZone(ZoneId.systemDefault());

        private static final MessageFormat basicCertFormat = new MessageFormat(
                """
                        "version"            : "v{0}",
                        "serial number"      : "{1}",
                        "signature algorithm": "{2}",
                        "issuer"             : "{3}",
                        "not before"         : "{4}",
                        "not  after"         : "{5}",
                        "subject"            : "{6}",
                        "subject public key" : "{7}"
                        """,
                Locale.ENGLISH);

        private static final MessageFormat extendedCertFormart =
            new MessageFormat(
                    """
                            "version"            : "v{0}",
                            "serial number"      : "{1}",
                            "signature algorithm": "{2}",
                            "issuer"             : "{3}",
                            "not before"         : "{4}",
                            "not  after"         : "{5}",
                            "subject"            : "{6}",
                            "subject public key" : "{7}",
                            "extensions"         : [
                            {8}
                            ]
                            """,
                Locale.ENGLISH);

        //
        // private static MessageFormat certExtFormat = new MessageFormat(
        //         "{0} [{1}] '{'\n" +
        //         "  critical: {2}\n" +
        //         "  value: {3}\n" +
        //         "'}'",
        //         Locale.ENGLISH);
        //

        private static final MessageFormat messageFormatNoParas =
            new MessageFormat(
                    """
                            '{'
                              "logger"      : "{0}",
                              "level"       : "{1}",
                              "thread id"   : "{2}",
                              "thread name" : "{3}",
                              "time"        : "{4}",
                              "caller"      : "{5}",
                              "message"     : "{6}"
                            '}'
                            """,
                Locale.ENGLISH);

        private static final MessageFormat messageCompactFormatNoParas =
            new MessageFormat(
                "{0}|{1}|{2}|{3}|{4}|{5}|{6}\n",
                Locale.ENGLISH);

        private static final MessageFormat messageFormatWithParas =
            new MessageFormat(
                    """
                            '{'
                              "logger"      : "{0}",
                              "level"       : "{1}",
                              "thread id"   : "{2}",
                              "thread name" : "{3}",
                              "time"        : "{4}",
                              "caller"      : "{5}",
                              "message"     : "{6}",
                              "specifics"   : [
                            {7}
                              ]
                            '}'
                            """,
                Locale.ENGLISH);

        private static final MessageFormat messageCompactFormatWithParas =
            new MessageFormat(
                    """
                            {0}|{1}|{2}|{3}|{4}|{5}|{6} (
                            {7}
                            )
                            """,
                Locale.ENGLISH);

        private static final MessageFormat keyObjectFormat = new MessageFormat(
                """
                        "{0}" : '{'
                        {1}'}'
                        """,
                Locale.ENGLISH);



    }
}
