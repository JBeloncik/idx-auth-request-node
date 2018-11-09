package com.daon.idxAuthRequestNode;

import com.daon.identityx.rest.model.pojo.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.collections.UserCollection;
import com.identityx.clientSDK.credentialsProviders.EncryptedKeyPropFileCredentialsProvider;
import com.identityx.clientSDK.exceptions.ClientInitializationException;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.queryHolders.UserQueryHolder;
import com.identityx.clientSDK.repositories.UserRepository;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class IdxCommon {
    
    static ObjectMapper objectMapper = new ObjectMapper();

    private static final Logger logger = LoggerFactory.getLogger("amAuth");

    static User findUser(String userId, TenantRepoFactory tenantRepoFactory) throws NodeProcessException {
        UserRepository userRepo = tenantRepoFactory.getUserRepo();
        UserQueryHolder holder = new UserQueryHolder();
        holder.getSearchSpec().setUserId(userId);
        UserCollection userCollection;
        try {
            userCollection = userRepo.list(holder);
        } catch (IdxRestException e) {
            throw new NodeProcessException(e);
        }

        if (userCollection == null)	{
            return null;
        }
        if (userCollection.getItems() == null) {
            return null;
        }
        switch (userCollection.getItems().length) {
            case 0:
                return null;
            case 1:
                return userCollection.getItems()[0];
            default:
                String error = "More than one user with the same UserId";
                logger.error(error);
                return null;
        }
    }

    static TenantRepoFactory getTenantRepoFactory(TreeContext context) throws NodeProcessException {
        TenantRepoFactory tenantRepoFactory;

        //Pull these config values from SharedState. These are in the IdxCheckEnrollmentStatus node
        String pathToKeyStore = context.sharedState.get("IdxPathToKeyStore").asString();
        if (pathToKeyStore == null) {
            logger.error("Error: Path to JKS KeyStore not found in SharedState!");
            throw new NodeProcessException("Path to JKS KeyStore not found!");
        }

        InputStream keyStore;
        try {
            keyStore = new FileInputStream(new File(pathToKeyStore));
        } catch (FileNotFoundException e) {
            logger.error("Cannot open keystore file");
            throw new NodeProcessException(e);
        }

        String pathToCredentialProperties = context.sharedState.get("IdxPathToCredentialProperties").asString();

        if (pathToCredentialProperties == null) {
            logger.error("Error: Path to credential.properties file not found in SharedState!");
            throw new NodeProcessException("Path to credential.properties file not found!");
        }
        InputStream credentialsProperties;
        try {
            credentialsProperties = new FileInputStream(new File(pathToCredentialProperties));
        } catch (FileNotFoundException e) {
            logger.error("Cannot open credential properties file");
            throw new NodeProcessException(e);
        }

        String jksPassword = context.sharedState.get("IdxJksPassword").asString();
        if (jksPassword == null) {
            logger.error("Error: JKS Password not found in SharedState!");
            throw new NodeProcessException("JKS password not found in SharedState!");
        }

        String keyAlias = context.sharedState.get("IdxKeyAlias").asString();
        if (keyAlias == null) {
            logger.error("Error: Key Alias not found in SharedState!");
            throw new NodeProcessException("Key Alias not found in SharedState!");
        }

        String keyPassword = context.sharedState.get("IdxKeyPassword").asString();
        if (keyPassword == null) {
            logger.error("Error: Key Password not found in SharedState!");
            throw new NodeProcessException("Key password not found in SharedState!");
        }

        EncryptedKeyPropFileCredentialsProvider provider;
        try {
            provider = new EncryptedKeyPropFileCredentialsProvider(keyStore,
                    jksPassword, credentialsProperties, keyAlias, keyPassword);
        } catch (ClientInitializationException e) {
            logger.error("Cannot initialize encrypted key property file");
            throw new NodeProcessException(e);
        }

        try {
            tenantRepoFactory = new TenantRepoFactory(provider);
        } catch (IdxRestException e) {
            logger.debug("An exception occurred connecting to the IX Server");
            throw new NodeProcessException(e);
        }
        return tenantRepoFactory;
    }
}
