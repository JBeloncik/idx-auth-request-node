package com.daon.idxAuthRequestNode;

import com.daon.identityx.rest.model.pojo.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.collections.UserCollection;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.queryHolders.UserQueryHolder;
import com.identityx.clientSDK.repositories.UserRepository;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class IdxCommon {
    
    static ObjectMapper objectMapper = new ObjectMapper();

    private static final Logger logger = LoggerFactory.getLogger("amAuth");
    static final String IDX_HREF_KEY = "idx-auth-ref-shared-state-key";

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

        String pathToCredentialProperties = context.sharedState.get("IdxPathToCredentialProperties").asString();

        if (pathToCredentialProperties == null) {
            logger.error("Error: Path to credential.properties file not found in SharedState!");
            throw new NodeProcessException("Path to credential.properties file not found!");
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

        try {
            tenantRepoFactory = IdxTenantRepoFactorySingleton.getInstance(pathToKeyStore, jksPassword,
                    pathToCredentialProperties, keyAlias, keyPassword).tenantRepoFactory;
        } catch (IdxRestException e) {
            logger.debug("An exception occurred using the tenantRepoFactorySingleton");
            throw new NodeProcessException("Error using tenantRepoFactorySingleton");
        }

        if (tenantRepoFactory != null) {
            logger.debug("Connected to the IdentityX Server");
        } else {
            logger.debug("Error creating tenantRepoFactory");
            throw new NodeProcessException("Error creating tenantRepoFactory");
        }

        return tenantRepoFactory;
    }
}
