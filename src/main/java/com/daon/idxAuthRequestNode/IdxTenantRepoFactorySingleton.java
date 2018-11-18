package com.daon.idxAuthRequestNode;

import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.credentialsProviders.EncryptedKeyPropFileCredentialsProvider;
import com.identityx.clientSDK.def.ICredentialsProvider;
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
                                String keyAlias, String keyPass) throws IdxRestException
    {
        try {

            InputStream keyStore = new FileInputStream(new File(keyStorePath));
            InputStream credentialProperties = new FileInputStream(new File(credentialPropertiesPath));

            ICredentialsProvider tenantCredentialProvider = new EncryptedKeyPropFileCredentialsProvider(keyStore,
                    jksPassword, credentialProperties, keyAlias, keyPass);

            tenantRepoFactory = new TenantRepoFactory(tenantCredentialProvider);

        } catch (IdxRestException e) {
            e.printStackTrace();
        } catch (ClientInitializationException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    static IdxTenantRepoFactorySingleton getInstance(String keyStorePath, String jksPassword,
                                                     String credentialPropertiesPath, String keyAlias, String keyPass) throws IdxRestException
    {
        if(tenantRepoInstance == null)
        {
            tenantRepoInstance = new IdxTenantRepoFactorySingleton(keyStorePath, jksPassword, credentialPropertiesPath,
                    keyAlias, keyPass);
        }
        return tenantRepoInstance;
    }

}
