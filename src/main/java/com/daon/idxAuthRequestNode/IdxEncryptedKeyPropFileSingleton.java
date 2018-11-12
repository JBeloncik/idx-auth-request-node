package com.daon.idxAuthRequestNode;

import com.identityx.clientSDK.credentialsProviders.EncryptedKeyPropFileCredentialsProvider;
import com.identityx.clientSDK.exceptions.ClientInitializationException;
import java.io.InputStream;

class IdxEncryptedKeyPropFileSingleton {

    // static variable single_instance of type IdxEncryptedKeyPropFileSingleton
    private static IdxEncryptedKeyPropFileSingleton single_instance = null;

    // variable of type EncryptedKeyPropFileCredentialsProvider
    EncryptedKeyPropFileCredentialsProvider provider;

    // private constructor restricted to this class itself
    private IdxEncryptedKeyPropFileSingleton(InputStream jksInputStream, String jksPassword,
                                             InputStream credentialsInputStream, String keyAlias,
                                             String keyPassword) throws ClientInitializationException {
        provider = new EncryptedKeyPropFileCredentialsProvider(jksInputStream, jksPassword, credentialsInputStream,
                keyAlias, keyPassword);
    }

    // static method to create instance of IdxEncryptedKeyPropFileSingleton class
    static IdxEncryptedKeyPropFileSingleton getInstance(InputStream jksInputStream, String jksPassword
            , InputStream credentialsInputStream, String keyAlias, String keyPassword) throws ClientInitializationException {
        if (single_instance == null)
            single_instance = new IdxEncryptedKeyPropFileSingleton(jksInputStream, jksPassword, credentialsInputStream,
                    keyAlias, keyPassword);

        return single_instance;
    }

}
