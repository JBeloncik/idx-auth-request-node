package com.daon.idxAuthRequestNode;

import org.forgerock.openam.auth.node.api.NodeProcessException;

import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.credentialsProviders.EncryptedKeyPropFileCredentialsProvider;
import com.identityx.clientSDK.exceptions.ClientInitializationException;
import com.identityx.clientSDK.exceptions.IdxRestException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

class IdxTenantRepoFactorySingleton {

    private static IdxTenantRepoFactorySingleton tenantRepoInstance = null;

    TenantRepoFactory tenantRepoFactory;

    private IdxTenantRepoFactorySingleton(String keyStorePath, String jksPassword, String credentialPropertiesPath,
                                String keyAlias, String keyPass) throws NodeProcessException {
        InputStream keyStore;
        InputStream credentialProperties;
        try {
            keyStore = new FileInputStream(new File(keyStorePath));
        } catch (FileNotFoundException e) {
            throw new NodeProcessException("Unable to find keystore file at: " + keyStorePath, e);
        }
        try {
            credentialProperties = new FileInputStream(new File(credentialPropertiesPath));
        } catch (FileNotFoundException e) {
            throw new NodeProcessException("Unable to find credential properties file at: " + credentialPropertiesPath, e);
        }
        try {
            tenantRepoFactory = new TenantRepoFactory(new EncryptedKeyPropFileCredentialsProvider(keyStore, jksPassword, credentialProperties, keyAlias, keyPass));
        } catch (IdxRestException | ClientInitializationException e) {
            throw new NodeProcessException(e);
        }
    }

    static IdxTenantRepoFactorySingleton getInstance(String keyStorePath, String jksPassword,
                                                     String credentialPropertiesPath, String keyAlias,
                                                     String keyPass) throws NodeProcessException {
        if(tenantRepoInstance == null) {
            tenantRepoInstance = new IdxTenantRepoFactorySingleton(keyStorePath, jksPassword, credentialPropertiesPath, keyAlias, keyPass);
        }
        return tenantRepoInstance;
    }

}
