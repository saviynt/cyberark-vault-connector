package com.saviynt.ssm.vaultconnector.cyberarkccp.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.saviynt.ssm.abstractConnector.VaultConfigVo;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.*;

public class CCPAdapterService {

    private static final Logger logger = LoggerFactory.getLogger(CCPAdapterService.class);

    private AuthenticationService authenticationService = null;

    public static final String CONNECTOR_FILES = "CONNECTORFILES";

    private static String constructUrlWithParams(String baseUrl, HashMap<String, Object> queryParams) {
        logger.debug("Inside constructUrlWithParams");
        if (queryParams.isEmpty()) {
            return baseUrl;
        }

        StringJoiner joiner = new StringJoiner("&", baseUrl + "?", "");
        for (Map.Entry<String, Object> entry : queryParams.entrySet()) {
            if(!(entry.getKey().equalsIgnoreCase("encryptionmechanism"))||
                    (entry.getKey().equalsIgnoreCase("ignoreMapping")))
            {
                String encodedKey = URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8);
                String encodedValue = URLEncoder.encode((String) entry.getValue(), StandardCharsets.UTF_8);
                joiner.add(encodedKey + "=" + encodedValue);
            }
        }
        logger.debug("Exiting constructUrlWithParams");
        return joiner.toString();
    }

    private static String makeRequestAndRetrieveAttribute(String url, String attributeName, String authCertPath, String passPhrase) {

        logger.debug("Inside makeRequestAndRetrieveAttribute");
        try {
            SSLContextBuilder sslContextBuilder = SSLContextBuilder.create();

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(authCertPath)) {
                keyStore.load(fis, passPhrase.toCharArray());
            }

            logger.debug("Keystore set");

            sslContextBuilder.loadKeyMaterial(
                    // Replace with the path to your P12 file and its password
                    keyStore,
                    passPhrase.toCharArray());

            logger.debug("Keystore loaded");

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                    sslContextBuilder.build());

            try (CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslsf).build()) {
                HttpGet httpGet = new HttpGet(url);

                try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                    String responseBody = EntityUtils.toString(response.getEntity());

                    logger.debug("Response from CCP : "+ responseBody);

                    // Parse JSON response
                    ObjectMapper objectMapper = new ObjectMapper();
                    JsonNode rootNode = objectMapper.readTree(responseBody);

                    // Retrieve attribute value
                    JsonNode attributeNode = rootNode.path(attributeName);
                    if (!attributeNode.isMissingNode()) {
                        return attributeNode.asText(); // Returns the value of the specified attribute
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return null; // Attribute not found or error occurred
    }

    public Map getSecretFromVault(Map<String, Object> vaultConfigData, Map<String, Object> data) {
        logger.debug("Entered in getSecretFromVault");
        Map responseData = new HashMap();
        Map valueMap = new HashMap();

        Map<String, Object> vaultConnAttrs = (Map<String, Object>) data.get("vaultConnectionAtributes");

        String url = (String) vaultConnAttrs.get("URL");
        String authCert = (String) vaultConnAttrs.get("AUTH_CERTIFICATE");
        String passphrase = (String) vaultConnAttrs.get("AUTH_CERTIFICATE_PASSPHRASE");

        logger.debug("read the attributes");

        authenticationService = new AuthenticationService();

        try {

            String authCertPath = authenticationService.getPEMKeyFilePath(authCert);

            logger.debug("certificate path:" + authCertPath);

            if (vaultConfigData != null) {
                Map<String, Object> vaultConfigJSON = (Map<String, Object>) vaultConfigData.get("keyMapping");

                logger.debug("keyMapping:" + vaultConfigJSON);


                if (data.containsKey("encryptedConnAttr")) {
                    Map<String, String> encryptedConnAttr = (Map<String, String>) data.get("encryptedConnAttr");

                    logger.debug("encryptedConnAttr:" + encryptedConnAttr);

                    for (Map.Entry<String, String> dataMap : encryptedConnAttr.entrySet()) {
                        String attributeName = (String) dataMap.getKey();
                        Map<String, Object> attributeJSONToBeProcessed = (HashMap<String, Object>) vaultConfigJSON.get(attributeName);

                        logger.debug("attributeName:"+ attributeName);
                        logger.debug("attributeJSONToBeProcessed:" + attributeJSONToBeProcessed);

                        if (Objects.isNull(attributeJSONToBeProcessed)) {
                            logger.warn("Vault config not configured for {}", attributeName);
                            continue;
                        } else {

                            String urlWithParams = constructUrlWithParams(url, (HashMap<String, Object>) attributeJSONToBeProcessed);
                            logger.debug("Constructed URL: " + urlWithParams);

                            String secretAttributeName = "Content"; // Replace with the actual attribute name you're interested in
                            String attributeValue = makeRequestAndRetrieveAttribute(urlWithParams, secretAttributeName, authCertPath, passphrase);

                            if (attributeValue != null) {
                                logger.debug(secretAttributeName + ": " + attributeValue);
                            } else {
                                logger.debug("Attribute '" + secretAttributeName + "' not found in the response.");
                            }

                            String keyName = (String) ((Map) vaultConfigJSON.get(attributeName)).get("keyName");

                            valueMap.put(attributeName, attributeValue);


                        }

                    }

                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        responseData.put("encryptedConnAttr", valueMap);
        responseData.put("status", "success");

        logger.debug("Exit in getSecretFromVault");
        return responseData;
    }

    public void setVaultExternalConnectionType(VaultConfigVo configData) {
        List<String> connectionAttributes = configData.getConnectionAttributes();
		/*
		  INTGN-2165
		  adapterAttributes will added in the beginning of connection page in same order defined below
		  then existing attributes from (configData.getConnectionAttributes()) will be added at the end of the connection page
		*/
        String[] adapterAttributes = new String[]{
                "URL",
                "AUTH_CERTIFICATE",
                "AUTH_CERTIFICATE_PASSPHRASE"
        };
        List<String> allAttributes = new ArrayList<String>(Arrays.asList(adapterAttributes));
        allAttributes.addAll(connectionAttributes);
        allAttributes.remove("VAULTAPIMAPPINGJSON");
        configData.setConnectionAttributes(allAttributes);

        List<String> encryptedConnectionAttributes = configData.getEncryptedConnectionAttributes();
        encryptedConnectionAttributes.add("AUTH_CERTIFICATE_PASSPHRASE");
        JSONObject jsonObject = null;
        String ConnectionAttributesDescription = configData.getConnectionAttributesDescription();
        if (StringUtils.isNotEmpty(ConnectionAttributesDescription)) {
            jsonObject = new JSONObject(ConnectionAttributesDescription);
        } else {
            jsonObject = new JSONObject();
        }

        for (String k : allAttributes) {
            if (k.endsWith("JSON")) {

            } else {
                jsonObject.put(k, "Value of  " + k);
            }

        }

        jsonObject.put("URL", "Enter CCP URL e.g. https://<IIS server>/AIMWebService/api/Accounts");
        jsonObject.put("AUTH_CERTIFICATE", "Provide PFX file name which should be used for CCP client certificate authentication");
        jsonObject.put("AUTH_CERTIFICATE_PASSPHRASE", "Provide passphrase to be used alongside AUTH_CERTIFICATE");

        configData.setConnectionAttributesDescription(jsonObject.toString());

        List<String> requiredConnectionAttributes = configData.getRequiredConnectionAttributes();
        requiredConnectionAttributes.add("URL");
        requiredConnectionAttributes.add("AUTH_CERTIFICATE");
        requiredConnectionAttributes.add("AUTH_CERTIFICATE_PASSPHRASE");

    }
}


