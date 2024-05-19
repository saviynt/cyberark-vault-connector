package com.saviynt.ssm.vaultconnector.cyberark.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.saviynt.ssm.vaultconnector.cyberark.CyberArkVaultConnector;
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


public class CCPAuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(CCPAuthenticationService.class);


    public boolean testCCPConnection(String url, Map<String, Object> data) throws Exception{

        logger.info("Entered in testCCPConnection() method");
        boolean status = false;

        String authCert = (String) data.get("CCP_AUTH_CERTIFICATE");
        String passphrase = (String) data.get("CCP_AUTH_CERTIFICATE_PASSPHRASE");
        String hostName = (String) data.get("HOSTNAME");

        try {

            String authCertPath = getPEMKeyFilePath(authCert);

            logger.info("Using " + authCert + " certificate for authentication to CCP host:"+hostName);

            KeyStore keyStore = KeyStore.getInstance("PKCS12");

            FileInputStream fis = new FileInputStream(authCertPath);

            keyStore.load(fis, passphrase.toCharArray());

            SSLContextBuilder sslContextBuilder = SSLContextBuilder.create();

            sslContextBuilder.loadKeyMaterial(keyStore, passphrase.toCharArray());

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContextBuilder.build());

            CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslsf).build();

            url = String.format(url, hostName);

            logger.info("Calling CCP test connection url:"+url);

            HttpGet httpGet = new HttpGet(url);

            CloseableHttpResponse response = httpClient.execute(httpGet);
            // Assuming response body is UTF-8
            String responseBody = EntityUtils.toString(response.getEntity());

            logger.info("test connection response:"+ responseBody);

            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode rootNode = objectMapper.readTree(responseBody);

            // Assuming the error message structure is {"ErrorCode": "AIMWS031E", "ErrorMsg": "..."}
            if (rootNode.has("ErrorCode") && rootNode.get("ErrorCode").asText().equals("AIMWS031E")) {
                logger.info("Response contains expected error for missing AppID parameter, which confirms test connection is successful");
                status = true;
            }

        } catch (Exception e) {
            logger.error("Exception occurred in testCCPConnection() method : ", e);
            throw e;
        }
        logger.info("Exiting from testCCPConnection() method, connection status:" + status);
        return status;
    }

    public String getPEMKeyFilePath(String pemKeyFile) throws Exception {
        logger.info("Entered in getPEMKeyFilePath() method");

        try {
            if (new File(pemKeyFile).exists())
                return pemKeyFile;
            logger.info("Checking PEM key file in other specified folder locations");

            String connectorFilesPath = System.getenv(CyberArkVaultConnector.CONNECTOR_FILES);
            if (!StringUtils.isEmpty(connectorFilesPath)) {
                if (!connectorFilesPath.endsWith("/"))
                    connectorFilesPath = connectorFilesPath + "/";
                pemKeyFile = connectorFilesPath + pemKeyFile;
                logger.info("Found the PEM key file specified in CCP_AUTH_CERTIFICATE");
            }
            if (!new File(pemKeyFile).exists()) {
                logger.error("PEM key file specified in CCP_AUTH_CERTIFICATE is not found");
                throw new Exception("PEM key file specified in CCP_AUTH_CERTIFICATE is not found");
            }
        }
        catch(Exception e)
        {
            logger.error("Error occurred in getPEMKeyFilePath",e);
            throw e;
        }
        logger.info("Exiting from getPEMKeyFilePath method");
        return pemKeyFile;
    }


}

