package com.saviynt.ssm.vaultconnector.cyberarkccp.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Map;


public class AuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);


    public boolean testConnection(Map<String, Object> data) {

        logger.debug("Entered in testConnection() method");

        boolean status = false;
        String url = (String) data.get("URL");
        String authCert = (String) data.get("AUTH_CERTIFICATE");
        String passphrase = (String) data.get("AUTH_CERTIFICATE_PASSPHRASE");

        logger.debug("read connection values");

        try {

            String authCertPath = getPEMKeyFilePath(authCert);

            logger.debug("cert path:" + authCertPath);

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(authCertPath)) {
                keyStore.load(fis, passphrase.toCharArray());
            }

            SSLContextBuilder sslContextBuilder = SSLContextBuilder.create();


            sslContextBuilder.loadKeyMaterial(
                    // Replace with the path to your P12 file and its password
                    keyStore,
                    passphrase.toCharArray());

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                    sslContextBuilder.build());

            logger.debug("calling test connection url:"+url);
            try (CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslsf).build()) {
                HttpGet httpGet = new HttpGet(url);

                try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                    // Assuming response body is UTF-8
                    String responseBody = EntityUtils.toString(response.getEntity());

                    logger.debug("test connection response:"+ responseBody);
                    ObjectMapper objectMapper = new ObjectMapper();
                    JsonNode rootNode = objectMapper.readTree(responseBody);

                    // Assuming the error message structure is {"ErrorCode": "AIMWS031E", "ErrorMsg": "..."}
                    if (rootNode.has("ErrorCode") && rootNode.get("ErrorCode").asText().equals("AIMWS031E")) {
                        System.out.println("Detected specific error code: AIMWS031E");
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        logger.debug("Exiting from testConnection() method");
        return status;
    }

    public String getPEMKeyFilePath(String pemKeyFile) throws Exception {
        logger.debug("Entered in getPEMKeyFilePath() method");
        if (new File(pemKeyFile).exists())
            return pemKeyFile;
        logger.debug("Checking PEM key file in other specified folder locations");
        String connectorFilesPath = System.getenv(CCPAdapterService.CONNECTOR_FILES);
        if (!StringUtils.isEmpty(connectorFilesPath)) {
            if (!connectorFilesPath.endsWith("/"))
                connectorFilesPath = connectorFilesPath + "/";
            pemKeyFile = connectorFilesPath + pemKeyFile;
        }
        if (!new File(pemKeyFile).exists()) {
            logger.error("PEM key file specified in AUTH_CREDENTIAL_VALUE is not found");
            throw new Exception("PEM key file specified in AUTH_CREDENTIAL_VALUE is not found");
        }
        return pemKeyFile;

    }

}

