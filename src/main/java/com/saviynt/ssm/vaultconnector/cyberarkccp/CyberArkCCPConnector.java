package com.saviynt.ssm.vaultconnector.cyberarkccp;

import com.saviynt.ssm.abstractConnector.VaultConfigVo;
import com.saviynt.ssm.abstractConnector.VaultConnectorSpecification;
import com.saviynt.ssm.abstractConnector.exceptions.*;
import com.saviynt.ssm.vaultconnector.cyberarkccp.service.AuthenticationService;
import com.saviynt.ssm.vaultconnector.cyberarkccp.service.CCPAdapterService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

public class CyberArkCCPConnector extends VaultConnectorSpecification {

    private static final long serialVersionUID = 1L;

    private static final Logger logger = LoggerFactory.getLogger(CyberArkCCPConnector.class);

    private AuthenticationService authenticationService = null;

    private CCPAdapterService ccpAdapterService = null;

    public String displayName() {
        return "CyberArk CCP";
    }

    public String version() {
        return "1.0";
    }

    public Map getSecret(Map<String, Object> vaultConfigData, Map<String, Object> data) throws ConnectorException {
        logger.debug("Entered in getSecret");
        Map returnData = new HashMap();
        try {
            ccpAdapterService = new CCPAdapterService();
            Map encryptedDataFromVault = ccpAdapterService.getSecretFromVault(vaultConfigData, data);
            returnData.put("encryptedConnAttr", encryptedDataFromVault);
            returnData.put("status", "success");
        } catch (Exception e) {
            logger.error("Error occurred in getSecret()", e);
            throw new ConnectorException(e.getMessage());
        }
        logger.debug("Exit in getSecret");
        return returnData;
    }

    @Override
    public Map setSecret(Map<String, Object> vaultConfigData, Map<String, Object> data) throws ConnectorException {
        return null;
    }

    public Map test(Map<String, Object> vaultConfigData, Map<String, Object> data) throws ConnectorException,
            InvalidCredentialException, InvalidAttributeValueException, OperationTimeoutException, MissingKeyException {
        logger.debug("Entered in test() method");
        Map respMap = new HashMap();
        try {
            AuthenticationService authenticationService = new AuthenticationService();
            boolean status = authenticationService.testConnection(data);
            respMap.put("status", status);

        } catch (Exception e) {
            logger.error("Exception occured in test() method : ", e);
            respMap.put("status", false);
        }
        logger.debug("Exit in test() method");
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
        ccpAdapterService = new CCPAdapterService();
        ccpAdapterService.setVaultExternalConnectionType(configData);
    }

    public Map dataFormatting(Map vaultConfigJSON) {
        // TODO Auto-generated method stub
        return null;
    }

}
