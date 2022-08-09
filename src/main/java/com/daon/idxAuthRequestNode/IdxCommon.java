package com.daon.idxAuthRequestNode;

import com.daon.identityx.rest.model.def.UserStatusEnum;
import com.daon.identityx.rest.model.pojo.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.collections.UserCollection;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.queryHolders.UserQueryHolder;
import com.identityx.clientSDK.repositories.UserRepository;

import java.net.MalformedURLException;
import java.net.URL;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.utils.StringUtils;

class IdxCommon {
    
    static ObjectMapper objectMapper = new ObjectMapper();
    
    private static LoggerWrapper logger = new LoggerWrapper();
    
    static final String IDX_HREF_KEY = "idx-auth-ref-shared-state-key";
    static final String IDX_USER_KEY = "idx-user-object-shared-state-key";
    
    static final String IDX_USER_HREF_KEY = "idx-user-href-shared-state-key";
    static final String IDX_USER_INTERNAL_ID_KEY = "idx-user-internal-id-shared-state-key";
    static final String IDX_USER_ID_KEY = "idx-user-id-shared-state-key";
    static final String IDX_AUTH_RESPONSE_KEY =  "idx-fido-auth-response-shared-state-key";
    
    static final String IDX_AUTH_RESPONSE_PROPERTY_NAME = "fidoAuthenticationResponse";
    static final String IDX_AUTH_REQUEST_TYPE = "FI";
    
    
    static User findUser(String userId, TenantRepoFactory tenantRepoFactory) throws NodeProcessException {
        UserRepository userRepo = tenantRepoFactory.getUserRepo();
        UserQueryHolder holder = new UserQueryHolder();
        holder.getSearchSpec().setUserId(userId);
        holder.getSearchSpec().setStatus(UserStatusEnum.ACTIVE);
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
                String error = "More than one Daon user with the same UserId";
                logger.error(error);
                throw new NodeProcessException(error);
        }
    }

    static TenantRepoFactory getTenantRepoFactory(TreeContext context) throws NodeProcessException {
        TenantRepoFactory tenantRepoFactory;

        //Pull these config values from SharedState. These are in the IdxCheckEnrollmentStatus node
        String tenantUrl = context.sharedState.get("IdxTenantUrl").asString();
        if (tenantUrl == null) {
            logger.error("Error: Tenant URL not found in SharedState!");
            throw new NodeProcessException("Tenant URL not found!");
        }

        String user_name = context.sharedState.get("IdxUser").asString();

        if (user_name == null) {
            logger.error("Error: Username not found in SharedState!");
            throw new NodeProcessException("Username not found!");
        }

        String password = context.sharedState.get("IdxPassword").asString();
        if (password == null) {
            logger.error("Error: Password not found in SharedState!");
            throw new NodeProcessException("Password not found in SharedState!");
        }
        

        tenantRepoFactory = IdxTenantRepoFactorySingleton.getInstance(tenantUrl, user_name, password).tenantRepoFactory;

        if (tenantRepoFactory != null) {
            logger.debug("Successfully Initialised the TenantRepoFactory");
        } else {
        	logger.error("Failure to Initialised the TenantRepoFactory");
            throw new NodeProcessException("Error creating tenantRepoFactory");
        }

        return tenantRepoFactory;
    }
    
    static String getServerName(String href) {

		logger.info("Entering getServerName");

		String server = null;

		if (StringUtils.isNotEmpty(href)) {

			URL url;

			try {

				url = new URL(href);

				String host = url.getHost();
				int port = url.getPort();

				if (port == -1) {
					server = String.format("%s", host);
				} else {
					server = String.format("%s:%d", host, port);
				}

			} catch (MalformedURLException ex) {
				logger.error("getServerName Exception", ex);
			}
		}

		logger.info("Exiting getServerName");
		return server;
	}
}
