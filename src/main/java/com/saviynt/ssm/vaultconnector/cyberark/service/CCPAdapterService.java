package com.saviynt.ssm.vaultconnector.cyberark.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.saviynt.ssm.abstractConnector.exceptions.ConnectorException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;

public class CCPAdapterService {

    private static final Logger logger = LoggerFactory.getLogger(CCPAdapterService.class);

    private CCPAuthenticationService authenticationService = null;

    private static String constructUrlWithParams(String baseUrl, HashMap<String, Object> queryParams) throws Exception{
        logger.info("Inside constructUrlWithParams");
        StringJoiner joiner = null;
        try {
            if (queryParams.isEmpty()) {
                return baseUrl;
            }

            joiner = new StringJoiner("&", baseUrl + "?", "");
            for (Map.Entry<String, Object> entry : queryParams.entrySet()) {
                if (!((entry.getKey().equalsIgnoreCase("encryptionmechanism")) ||
                        (entry.getKey().equalsIgnoreCase("ignoreMapping")))) {
                    String encodedKey = URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8);
                    String encodedValue = URLEncoder.encode((String) entry.getValue(), StandardCharsets.UTF_8);
                    joiner.add(encodedKey + "=" + encodedValue);
                }
            }
        }
        catch(Exception e)
        {
            logger.error("Error occurred in constructUrlWithParams",e);
            throw e;
        }
        logger.info("Exiting constructUrlWithParams");
        return joiner.toString();
    }

    private static String makeRequestAndRetrieveAttribute(String url, String attributeName, String authCertPath, String passPhrase) throws Exception{

        logger.info("Inside makeRequestAndRetrieveAttribute");
        String secretValue = null;
        try {
            SSLContextBuilder sslContextBuilder = SSLContextBuilder.create();

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream(authCertPath);
            keyStore.load(fis, passPhrase.toCharArray());
            sslContextBuilder.loadKeyMaterial(keyStore, passPhrase.toCharArray());

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContextBuilder.build());

            CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
            HttpGet httpGet = new HttpGet(url);

            CloseableHttpResponse response = httpClient.execute(httpGet);
            if(null!=response) {

                String responseBody = EntityUtils.toString(response.getEntity());

                logger.info("Parsing response received from CCP...");

                // Parse JSON response
                ObjectMapper objectMapper = new ObjectMapper();
                JsonNode rootNode = objectMapper.readTree(responseBody);

                // Retrieve attribute value
                JsonNode attributeNode = rootNode.path(attributeName);
                if (!attributeNode.isMissingNode()) {
                    secretValue = attributeNode.asText(); // Returns the value of the specified attribute
                }
            }
            else
            {
                throw new ConnectorException("No response received from CCP");
            }

        }
        catch (Exception e) {
            logger.error("Error occurred in makeRequestAndRetrieveAttribute",e);
            throw e;
        }
        logger.info("Exiting from makeRequestAndRetrieveAttribute");
        return secretValue; // Attribute not found or error occurred
    }

    public Map getSecretFromVault(Map<String, Object> vaultConfigData, Map<String, Object> data, String ccpUrl) throws Exception{
        logger.info("Entered in CCPAdapterService --> getSecretFromVault");
        Map responseData = new HashMap();
        Map valueMap = new HashMap();

        try {

            Map<String, Object> vaultConnAttrs = (Map<String, Object>) data.get("vaultConnectionAtributes");

            ccpUrl = String.format(ccpUrl, (String) vaultConnAttrs.get("HOSTNAME"));

            String authCert = (String) vaultConnAttrs.get("CCP_AUTH_CERTIFICATE");
            String passphrase = (String) vaultConnAttrs.get("CCP_AUTH_CERTIFICATE_PASSPHRASE");

            authenticationService = new CCPAuthenticationService();

            String authCertPath = authenticationService.getPEMKeyFilePath(authCert);

            if (vaultConfigData != null) {
                Map<String, Object> vaultConfigJSON = (Map<String, Object>) vaultConfigData.get("keyMapping");

                if (data.containsKey("encryptedConnAttr")) {
                    Map<String, String> encryptedConnAttr = (Map<String, String>) data.get("encryptedConnAttr");

                    for (Map.Entry<String, String> dataMap : encryptedConnAttr.entrySet()) {
                        String attributeName = (String) dataMap.getKey();
                        Map<String, Object> attributeJSONToBeProcessed = (HashMap<String, Object>) vaultConfigJSON.get(attributeName);

                        logger.info("Parameter Name:" + attributeName);
                        logger.info("Corresponding vault config:" + attributeJSONToBeProcessed);

                        if (Objects.isNull(attributeJSONToBeProcessed)) {
                            logger.error("Vault config not configured for {}", attributeName);
                            throw new ConnectorException("Vault config not configured for "+attributeName);
                        } else {

                            String urlWithParams = constructUrlWithParams(ccpUrl, (HashMap<String, Object>) attributeJSONToBeProcessed);
                            logger.info("Constructed URL: " + urlWithParams);

                            String secretAttributeName = "Content"; // Replace with the actual attribute name you're interested in
                            String attributeValue = makeRequestAndRetrieveAttribute(urlWithParams, secretAttributeName, authCertPath, passphrase);

                            if (attributeValue != null) {
                                logger.info("SecretValue fetched from vault");
                            } else {
                                logger.info("Attribute " + secretAttributeName + " not found in the response");
                                throw new ConnectorException("Attribute " + secretAttributeName + " not found in the response");
                            }

                            valueMap.put(attributeName, attributeValue);
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Error occurred in CCPAdapterService --> getSecretFromVault", e);
            throw e;
        }
        responseData.put("encryptedConnAttr", valueMap);
        responseData.put("status", "success");

        logger.debug("Exiting from CCPAdapterService --> getSecretFromVault");
        return responseData;
    }
}


