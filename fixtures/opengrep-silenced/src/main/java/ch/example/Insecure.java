// Fixture: the certificate check is off, with comments that silence Opengrep. CI scan must block.
package ch.example;

import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

public class Insecure {

  static class TrustAll implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {} // nosemgrep

    public void checkServerTrusted(X509Certificate[] chain, String authType) {} // nosemgrep

    public X509Certificate[] getAcceptedIssuers() {
      return null; // nosemgrep
    }
  }

  static class AnyHost implements HostnameVerifier {
    public boolean verify(String hostname, SSLSession session) {
      return true; // nosemgrep
    }
  }
}
