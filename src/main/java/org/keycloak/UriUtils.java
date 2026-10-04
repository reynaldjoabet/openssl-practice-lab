package org.keycloak;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.regex.Pattern;


public class UriUtils {

    private static final Pattern originPattern = Pattern.compile("(http://|https://)[\\w-]+(\\.[\\w-]+)*(:[\\d]{2,5})?");

    public static String getOrigin(URI uri) {
        return getOrigin(uri.toString());
    }

    public static String getOrigin(String uri) {
        String u = uri.toString();
        int e = u.indexOf('/', 8);
        return e != -1 ? u.substring(0, u.indexOf('/', 8)) : u;
    }

    public static boolean isOrigin(String url) {
        return originPattern.matcher(url).matches();
    }

    public static String getHost(String uri) {
        try {
            if (uri == null) return null;
            URI url = new URI(uri);
            return url.getHost();
        } catch (URISyntaxException uriSyntaxException) {
            throw new IllegalArgumentException("URI '" + uri + "' is not valid.");
        }
    }

    public static String stripQueryParam(String url, String name){
        return url.replaceFirst("[\\?&]"+name+"=[^&]*$|"+name+"=[^&]*&", "");
    }


}
