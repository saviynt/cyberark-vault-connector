package com.saviynt.ssm.vaultconnector.cyberark.service;

import com.saviynt.ssm.abstractConnector.exceptions.ConnectorException;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Map;

public class PVWAAuthenticationService {
    private static final Logger logger = LoggerFactory.getLogger(PVWAAuthenticationService.class);

    public String testPVWAConnection(String url, Map<String, Object> data) throws Exception {

        logger.info("Entered in PVWAAuthenticationService --> testPVWAConnection() method");

        String token = null;
        String username = (String) data.get("PVWA_USERNAME");
        String password = (String) data.get("PVWA_PASSWORD");
        String hostname = (String) data.get("HOSTNAME");

        logger.info("Constructing URL based on inputs received for test connection, hostname: "+ hostname+" & username: "+ username);

        try {

            url = String.format(url, hostname);

            CloseableHttpClient client = HttpClients.createDefault();

            HttpPost httpPost = new HttpPost(url);

            logger.info("PVWA Auth URL: "+url);

            // Prepare JSON data
            String json = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password);
            StringEntity entity = new StringEntity(json);
            httpPost.setEntity(entity);
            httpPost.setHeader("Accept", "application/json");
            httpPost.setHeader("Content-type", "application/json");

            // Execute request
            logger.info("Calling API");
            HttpResponse response = client.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();

            // Check response status code
            if (statusCode == 200) {
                logger.info("Authentication successful. Status Code: " + statusCode);
                String responseBody = EntityUtils.toString(response.getEntity());
                token = responseBody.replaceAll("[{}\"\n]", "");

                if(null==token)
                {
                    logger.error("Received token value as null");
                    throw new ConnectorException("Error while fetching access token");
                }
                else
                {
                    logger.info("Fetched the auth token...");
                }
            } else {
                logger.info("Authentication failed. Status Code: " + statusCode);
            }
        } catch (Exception e) {
            logger.error("Error occurred in testPVWAConnection method : "+e);
            throw e;
        }
        logger.info("Exiting from testPVWAConnection method execution");
        return token;
    }
}
