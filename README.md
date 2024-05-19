# Cyberark Vault Connector

The CyberArk Vault connector supports fetching secret from vault. It supports 2 modes of integration - PVWA and CCP.

1. PVWA mode of integration supports basic authentication.
2. CCP mode of integration supports client certificate based authentication.

This document outlines the steps to use this connector.

## Pre-Requisite:
1.	Please raise a Saviynt support ticket for registering the <b>[Connector Jar](https://github.com/saviynt/cyberark-vault-connector/blob/main/target/cyberark-vault-connector.jar)</b> in your EIC environment.

## Create connection type:
1. Log in to EIC.
2. Go to Connections -> Connection Type List -> Actions -> Create Connection Type.
3. Enter Connection Type Name as "CyberArkVault".
4. Select Enhanced Connector Framework as true, from the popup windows select "CyberArk Vault::1.0" -> Get Config.
5. This will populate default values -> click on Create.

## Create/Configure the CyberArk Vault connection:
1. Go to Connections -> Connection List -> Actions -> Create Connection.
2. Enter Connection Name "CyberArkVault".
3. Select Connection Type as "CyberArkVault".
4. Select Connector Version as "CyberArk Vault::1.0"
5. Configure rest parameters as below:

| Parameter Name | Description |
| -------- | ---------- |
| INTEGRATION_MODE | It is a mandatory parameter, expects administrator to configure CCP or PVWA here. Connector defaults to PVWA if invalid value is configured.  | 
| HOSTNAME | Enter CCP/PVWA hostname or IP address for e.g. server.example.com or 10.20.30.40 |
| PVWA_USERNAME | Enter Username to authenticate with PVWA service, this is used if INTEGRATION_MODE is PVWA |
| PVWA_PASSWORD | Enter Password to authenticate with PVWA service, this is used if INTEGRATION_MODE is PVWA |
| CCP_AUTH_CERTIFICATE | Enter PFX file name which will be used for CCP client certificate based authentication for e.g. TestCert.pfx, this is used if INTEGRATION_MODE is CCP. This file needs to be uploaded to File Directory -> Connector Files |
| CCP_AUTH_CERTIFICATE_PASSPHRASE | Provide passphrase to be used alongside CCP_AUTH_CERTIFICATE |

## Use CyberArk Vault connector to get secret in IGA connector:
1. Go to Connections -> Connection List -> Open a connection which requires to fetch a secret value from CyberArk vault, for e.g. any AD connection.
2. Select Credential Vault Connection as "CyberArkVault".
3. Click on Vault Config -> Advanced.
4. Depending on INTEGRATION_MODE used in CyberArkVault connection, enter the vault config.

If INTEGRATION_MODE is CCP:
```
{
  "encryptionmechanism": "None",
  "AppID": "App_Saviynt",
  "ignoreMapping": [
    "AppID",
    "Safe",
    "Object"
  ],
  "Safe": "Safe_Saviynt",
  "Object": "Operating System-DummyPlatform-dummy"
}
```
If INTEGRATION_MODE is PVWA:
```
{
  "reason": "EIC retrieval",
  "encryptionmechanism": "None",
  "ignoreMapping": [
    "AccountName",
    "SafeName",
    "reason",
    "TicketingSystemName"
  ],
  "SafeName": "Safe One",
  "TicketingSystemName": "SNOW",
  "AccountName": "Acct one"
}
```
### Important points to consider:
1. You can configure additional attribute mapping as per API support from CyberArk.
2. PVWA implementation uses SafeName and AccountName to internally fetch the AccountID and then corresponding secret value.
3. If you don't specify a parameter under ignoreMapping, connector automatically prefix the connection name before parameter value during API calls, for e.g. if you don't specify SafeName in ignoreMapping, connector will use "ConnectionName_Safe One" value, if you have AccountName and SafeName etc. created with connection name prefix in CyberArk target, you don't need to specify them in ignoreMapping, however if your objects don't have connection name as prefix in CyberArk target, specify them under ignoreMapping, so while calling CyberArk connector passes the value without prefixing connection name.
