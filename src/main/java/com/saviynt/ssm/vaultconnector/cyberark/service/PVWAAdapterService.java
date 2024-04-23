package com.saviynt.ssm.vaultconnector.cyberark.service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.saviynt.ssm.abstractConnector.exceptions.ConnectorException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class PVWAAdapterService {

    private static final Logger logger = LoggerFactory.getLogger(PVWAAdapterService.class);

    public Map getSecretFromVault(Map<String, Object> vaultConfigData, Map<String, Object> data, String pvwaAuthUrl, String pvwaApiUrl, String pvwaGetAccountsUrl) throws Exception{

        logger.info("Entered in PVWAAdpaterService --> getSecretFromVault");
        Map responseData = new HashMap();
        Map valueMap = new HashMap();

        try {

            logger.info("Fetching secret from PVWA");

            Map<String, Object> vaultConnAttrs = (Map<String, Object>) data.get("vaultConnectionAtributes");
            PVWAAuthenticationService pvwaAuthSrv = new PVWAAuthenticationService();

            String access_token = pvwaAuthSrv.testPVWAConnection(pvwaAuthUrl, vaultConnAttrs);

            if (vaultConfigData != null) {
                Map<String, Object> vaultConfigJSON = (Map<String, Object>) vaultConfigData.get("keyMapping");

                logger.info("keyMapping:" + vaultConfigJSON);

                if (data.containsKey("encryptedConnAttr")) {
                    Map<String, String> encryptedConnAttr = (Map<String, String>) data.get("encryptedConnAttr");

                    logger.info("encryptedConnAttr:" + encryptedConnAttr);

                    for (Map.Entry<String, String> dataMap : encryptedConnAttr.entrySet()) {
                        String attributeName = (String) dataMap.getKey();
                        Map<String, Object> attributeJSONToBeProcessed = (HashMap<String, Object>) vaultConfigJSON.get(attributeName);

                        logger.debug("attributeName:" + attributeName);
                        logger.debug("corresponding vault config:" + attributeJSONToBeProcessed);

                        if (Objects.isNull(attributeJSONToBeProcessed)) {
                            logger.error("Vault config not configured for {}", attributeName);
                            throw new ConnectorException("Vault config not configured for "+attributeName);

                        } else {

                            String accountName = (String) attributeJSONToBeProcessed.get("AccountName");

                            String safeName = (String) attributeJSONToBeProcessed.get("SafeName");

                            String filterValue = String.format("accountName eq '%s' and safeName eq '%s'", accountName, safeName);

                            // Encode the filter parameter value
                            String encodedFilterValue = URLEncoder.encode(filterValue, StandardCharsets.UTF_8.toString()).replace("+", "%20");

                            // Construct the URL with the encoded filter parameter value
                            pvwaGetAccountsUrl = String.format("http://%s/PasswordVault/API/Accounts?filter=%s",
                                    (String) vaultConnAttrs.get("HOSTNAME") , encodedFilterValue);

                            String accountID = getAccountID(pvwaGetAccountsUrl,access_token);

                            pvwaApiUrl = String.format(pvwaApiUrl, (String) vaultConnAttrs.get("HOSTNAME"), accountID);

                            String attributeValue = getPVWASecret(pvwaApiUrl, access_token, attributeJSONToBeProcessed);

                            if (attributeValue != null) {
                                //logger to be removed
                                logger.info("Value fetched from vault" + ": " + attributeValue);
                            } else {
                                logger.debug("No secret value fetched from target vault");
                            }

                            //String keyName = (String) ((Map) vaultConfigJSON.get(attributeName)).get("keyName");

                            valueMap.put(attributeName, attributeValue);


                        }

                    }

                }
            }

    } catch (Exception e) {

            logger.error("Error occurred in PVWAAdapterService --> getSecretFromVault", e);
            throw e;

        }
        responseData.put("encryptedConnAttr", valueMap);
        responseData.put("status", "success");

        logger.info("Exit from getSecretFromVault");
        return responseData;

}
    private String getAccountID(String pvwaAccountsURL, String access_token) throws Exception{

        logger.info("Entering getAccountID method");
        String accountID = null;
        // Create an HttpClient
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();

            logger.info("URL being called: "+ pvwaAccountsURL);
            // Create an HTTP GET request

            HttpGet httpGet = new HttpGet(pvwaAccountsURL);

            httpGet.setHeader("Authorization", "Bearer " + access_token);

            // Execute the request
            HttpResponse response = httpClient.execute(httpGet);

            // Get the response entity
            HttpEntity entity = response.getEntity();

            // Check if the response entity is not null
            if (entity != null) {
                // Parse the response JSON
                String responseBody = EntityUtils.toString(entity);
                logger.info("Response Body:" + responseBody);
                // Parse JSON response
                if (null != responseBody) {
                    JSONObject jsonObject = new JSONObject(responseBody);
                    if (jsonObject.has("id")) {
                        accountID = jsonObject.getString("id");
                    } else {
                        logger.error("No valid account ID found");
                        throw new ConnectorException("No valid account ID found");
                    }

                }
            }
        } catch (Exception e) {
            logger.error("Error occurred in getAccountID", e);
            throw e;
        }
        logger.info("Exiting from getAccountID, Account ID:"+ accountID);
        return accountID;
    }

    private String getPVWASecret(String pvwaAPIURL, String access_token, Map attributeJSONToBeProcessed) throws Exception{
        logger.info("Start execution getPVWASecret");

        String secret = null;
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            // Create an HTTP GET request
            logger.info("pvwaAPIURL: "+ pvwaAPIURL);
            HttpPost httpPost = new HttpPost(pvwaAPIURL);

            httpPost.setHeader("Authorization", "Bearer " + access_token);

            ObjectMapper objectMapper = new ObjectMapper();

            attributeJSONToBeProcessed.remove("AccountName");
            attributeJSONToBeProcessed.remove("SafeName");
            attributeJSONToBeProcessed.remove("ignoreMapping");
            attributeJSONToBeProcessed.remove("encryptionmechanism");

            String requestBody = objectMapper.writeValueAsString(attributeJSONToBeProcessed);

            if(null!=requestBody) {
                logger.info("requestBody: "+ requestBody);
                StringEntity requestEntity = new StringEntity(requestBody);
                httpPost.setEntity(requestEntity);
            }


            // Execute the request
            HttpResponse response = httpClient.execute(httpPost);


            if(null!=response)
            {
                // Get the response entity
                HttpEntity entity = response.getEntity();

                // Check if the response entity is not null
                if (entity != null) {
                    // Parse the response JSON
                    String responseBody = EntityUtils.toString(entity);
                    if (null != responseBody) {
                        secret = responseBody.substring(1, responseBody.length() - 1);
                    } else {
                        logger.error("No response returned");
                        throw new Exception("No secret value returned from target");
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Error occurred in getPVWASecret",e);
            throw e;
        }
        logger.info("Exiting from getPVWASecret");
        return secret;
    }

}
