package com.saviynt.ssm.vaultconnector.cyberark;

import com.saviynt.ssm.abstractConnector.VaultConfigVo;
import com.saviynt.ssm.abstractConnector.VaultConnectorSpecification;
import com.saviynt.ssm.abstractConnector.exceptions.*;
import com.saviynt.ssm.vaultconnector.cyberark.service.CCPAuthenticationService;
import com.saviynt.ssm.vaultconnector.cyberark.service.CCPAdapterService;
import com.saviynt.ssm.vaultconnector.cyberark.service.PVWAAdapterService;
import com.saviynt.ssm.vaultconnector.cyberark.service.PVWAAuthenticationService;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class CyberArkVaultConnector extends VaultConnectorSpecification {

    private static final long serialVersionUID = 1L;

    private static final Logger logger = LoggerFactory.getLogger(CyberArkVaultConnector.class);

    private CCPAuthenticationService authenticationService = null;

    private CCPAdapterService adapterService = null;

    public static final String CONNECTOR_FILES = "CONNECTORFILES";

    //update url to https
    public static final String PVWA_AUTH_URL = "http://%s/PasswordVault/API/auth/CyberArk/Logon";
    public static final String PVWA_API_URL = "http://%s/PasswordVault/API/Accounts/%s/Password/Retrieve";
    public static final String PVWA_GET_ACCOUNTS_URL = "http://%s/PasswordVault/API/Accounts?filter=%s";
    public static final String CCP_API_URL = "https://%s/AIMWebService/api/Accounts";

    public String displayName() {
        return "CyberArk Vault";
    }

    public String version() {
        return "1.0";
    }

    public Map getSecret(Map<String, Object> vaultConfigData, Map<String, Object> data) throws ConnectorException {
        logger.info("Entered in getSecret");
        Map encryptedDataFromVault = null;
        try {

            Map<String, Object> vaultConnAttrs = (Map<String, Object>) data.get("vaultConnectionAtributes");

            String integration_mode = (String) vaultConnAttrs.get("INTEGRATION_MODE");

            logger.info("INTEGRATION_MODE value input:"+ integration_mode);

            if (integration_mode.equalsIgnoreCase("CCP")) {
                logger.info("Integration mode is selected as CCP");
                CCPAdapterService ccpAdpSrv = new CCPAdapterService();
                encryptedDataFromVault = ccpAdpSrv.getSecretFromVault(vaultConfigData, data, CCP_API_URL);

            }
            // default value is considered as PVWA integration mode
            else
            {
                logger.info("Integration mode is selected as PVWA");
                PVWAAdapterService pvwaAdpSrv = new PVWAAdapterService();
                encryptedDataFromVault = pvwaAdpSrv.getSecretFromVault(vaultConfigData, data, PVWA_AUTH_URL, PVWA_API_URL, PVWA_GET_ACCOUNTS_URL);
            }

        } catch (Exception e) {
            logger.error("Error occurred in getSecret()", e);
            e.printStackTrace();
        }
        logger.info("Exit from getSecret");
        return encryptedDataFromVault;
    }

    @Override
    public Map setSecret(Map<String, Object> vaultConfigData, Map<String, Object> data) throws ConnectorException {
        return null;
    }

    public Map test(Map<String, Object> vaultConfigData, Map<String, Object> data) throws ConnectorException,
            InvalidCredentialException, InvalidAttributeValueException, OperationTimeoutException, MissingKeyException {
        logger.info("Entered in test() method");
        Map respMap = new HashMap();

        boolean status = false;
        try {
            String integration_mode = (String) data.get("INTEGRATION_MODE");
            logger.info("INTEGRATION_MODE is selected as:"+ integration_mode);

            if (integration_mode.equalsIgnoreCase("CCP")) {
                CCPAuthenticationService ccpAuthService = new CCPAuthenticationService();
                status = ccpAuthService.testCCPConnection(CCP_API_URL,data);
             }
            else
            {
                PVWAAuthenticationService pvwaAuthService = new PVWAAuthenticationService();
                status = (pvwaAuthService.testPVWAConnection(PVWA_AUTH_URL, data)!=null)?true:false;
            }

            respMap.put("status", status);
        } catch (Exception e) {
            logger.error("Exception occurred in test() method : ", e);
            e.printStackTrace();
            respMap.put("status", false);
        }
        logger.info("Exit in test() method");
        return respMap;
    }

    public Map seal(Map<String, Object> vaultConfigData, Map<String, Object> data) throws ConnectorException {
        // TODO Auto-generated method stub
        return null;
    }

    public Map unseal(Map<String, Object> vaultConfigData, Map<String, Object> data) throws ConnectorException {
        // TODO Auto-generated method stub
        return null;
    }

    public void setVaultConfig(VaultConfigVo configData) {
        logger.debug("Entered in setVaultConfig");
        List<String> connectionAttributes = configData.getConnectionAttributes();
		/*
		  INTGN-2165
		  adapterAttributes will added in the beginning of connection page in same order defined below
		  then existing attributes from (configData.getConnectionAttributes()) will be added at the end of the connection page
		*/
            String[] adapterAttributes = new String[]{
                    "INTEGRATION_MODE",
                    "HOSTNAME",
                    "PVWA_USERNAME",
                    "PVWA_PASSWORD",
                    "CCP_AUTH_CERTIFICATE",
                    "CCP_AUTH_CERTIFICATE_PASSPHRASE"
            };
            List<String> allAttributes = new ArrayList<String>(Arrays.asList(adapterAttributes));
            allAttributes.addAll(connectionAttributes);
            allAttributes.remove("VAULTAPIMAPPINGJSON");
            configData.setConnectionAttributes(allAttributes);

            List<String> encryptedConnectionAttributes = configData.getEncryptedConnectionAttributes();
            encryptedConnectionAttributes.add("PVWA_PASSWORD");
            encryptedConnectionAttributes.add("CCP_AUTH_CERTIFICATE_PASSPHRASE");

            JSONObject jsonObject = null;
            String ConnectionAttributesDescription = configData.getConnectionAttributesDescription();
            if (StringUtils.isNotEmpty(ConnectionAttributesDescription)) {
                jsonObject = new JSONObject(ConnectionAttributesDescription);
            } else {
                jsonObject = new JSONObject();
            }

            jsonObject.put("INTEGRATION_MODE", "Select mode of integration");
            jsonObject.put("HOSTNAME", "Enter CCP/PVWA hostname or IP address");
            jsonObject.put("PVWA_USERNAME", "Enter Username to authenticate with PVWA service");
            jsonObject.put("PVWA_PASSWORD", "Enter Password to authenticate with PVWA service");
            jsonObject.put("CCP_AUTH_CERTIFICATE", "Enter PFX file name which will be used for CCP client certificate based authentication");
            jsonObject.put("CCP_AUTH_CERTIFICATE_PASSPHRASE", "Provide passphrase to be used alongside CCP_AUTH_CERTIFICATE");

            configData.setConnectionAttributesDescription(jsonObject.toString());

            List<String> requiredConnectionAttributes = configData.getRequiredConnectionAttributes();
            requiredConnectionAttributes.add("INTEGRATION_MODE");
            requiredConnectionAttributes.add("HOSTNAME");

            logger.debug("Exiting from setVaultConfig");
    }

    public Map dataFormatting(Map vaultConfigJSON) {
        // TODO Auto-generated method stub
        return null;
    }

}
