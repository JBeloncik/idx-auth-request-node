/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */


package com.daon.idxAuthRequestNode;

import com.daon.identityx.rest.model.def.PolicyStatusEnum;
import com.daon.identityx.rest.model.def.TransactionPushNotificationTypeEnum;
import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.daon.identityx.rest.model.pojo.User;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.collections.ApplicationCollection;
import com.identityx.clientSDK.collections.PolicyCollection;
import com.identityx.clientSDK.collections.UserCollection;
import com.identityx.clientSDK.credentialsProviders.EncryptedKeyPropFileCredentialsProvider;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.queryHolders.ApplicationQueryHolder;
import com.identityx.clientSDK.queryHolders.PolicyQueryHolder;
import com.identityx.clientSDK.queryHolders.UserQueryHolder;
import com.identityx.clientSDK.repositories.ApplicationRepository;
import com.identityx.clientSDK.repositories.AuthenticationRequestRepository;
import com.identityx.clientSDK.repositories.PolicyRepository;
import com.identityx.clientSDK.repositories.UserRepository;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.UUID;
import javax.inject.Inject;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A node that initiates an authentication request to IdentityX
 */
@Node.Metadata(outcomeProvider  = SingleOutcomeNode.OutcomeProvider.class,
               configClass      = IdxAuthRequestNode.Config.class)
public class IdxAuthRequestNode extends SingleOutcomeNode {

	private final Logger logger = LoggerFactory.getLogger("amAuth");

	/**
     * Configuration for the node.
     */
	interface Config {

    }

    /**
     * Create the node.
	 */
    @Inject
    public IdxAuthRequestNode() {
	}

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
    	String username = context.sharedState.get(SharedStateConstants.USERNAME).asString();
    	//TODO: validate the username in AM before moving on
		//will want to call the isActive method
		//if not active, direct user to a registration page of some kind

        TenantRepoFactory tenantRepoFactory;
		try {
			InputStream keyStore = new FileInputStream(new File("home/ubuntu/tomcat/daonconfig/IdentityXKeyWrapper" +
					 ".jks"));
			InputStream credentialsProperties = new FileInputStream(new File
					 ("home/ubuntu/tomcat/daonconfig/credential.properties"));
			EncryptedKeyPropFileCredentialsProvider provider = new EncryptedKeyPropFileCredentialsProvider(keyStore,
					 "password", credentialsProperties, "identityxCert", "password");
			tenantRepoFactory = new TenantRepoFactory(provider);
      		logger.debug("Connected to the IdentityX Server");
		} catch (Exception ex) {
			logger.debug("An exception occurred connecting to the IX Server: " + ex );
			throw new NodeProcessException(ex);
		}

		String authHref = generateAuthenticationRequest(username, "login", tenantRepoFactory);
		logger.debug("Auth href: " + authHref);

    	//Place the href value in sharedState
    	logger.debug("Setting auth URL in shared state...");
		String IDX_HREF_KEY = "idx-auth-ref-shared-state-key";
		JsonValue newState = context.sharedState.copy().put(IDX_HREF_KEY, authHref);

    	return goToNext().replaceSharedState(newState).build();
    }

    private String generateAuthenticationRequest(String userId, String policyName, TenantRepoFactory
		   tenantRepoFactory) throws NodeProcessException {

		AuthenticationRequest request = new AuthenticationRequest();
		if ((userId != null) && (userId.length() > 0)) {
			User user = this.findUser(userId, tenantRepoFactory);
			if (user == null) {
				String error = "Error retrieving user";
				logger.error(error);
				throw new NodeProcessException(error);
			}
			else {
				logger.debug("User found with ID " + userId);
				request.setUser(user);
			}
		}

		PolicyQueryHolder holder = new PolicyQueryHolder();
		holder.getSearchSpec().setPolicyId(policyName);
		holder.getSearchSpec().setStatus(PolicyStatusEnum.ACTIVE);
		PolicyRepository policyRepo = tenantRepoFactory.getPolicyRepo();
		PolicyCollection policyCollection = null;
		try {
			policyCollection = policyRepo.list(holder);
		} catch (IdxRestException e) {
			throw new NodeProcessException(e);
		}
		if(policyCollection.getItems().length > 0) {
			logger.debug("Setting Policy On Authentication Request");
			request.setPolicy(policyCollection.getItems()[0]);
		}
		else {
			//TODO Should this be an error case? If so need to trhwo a NodeProcessException
			logger.debug("Could not find an active policy with the PolicyId: " + policyName);
		}

		ApplicationRepository applicationRepo = tenantRepoFactory.getApplicationRepo();
		ApplicationQueryHolder applicationQueryHolder = new ApplicationQueryHolder();

		//TODO this need to be pulled out as configuration for administrator to enter
		applicationQueryHolder.getSearchSpec().setApplicationId("daonbank");
		ApplicationCollection applicationCollection = null;
		try {
			applicationCollection = applicationRepo.list(applicationQueryHolder);
		} catch (IdxRestException e) {
			throw new NodeProcessException(e);
		}

		if (applicationCollection.getItems().length > 0) {
			request.setApplication(applicationCollection.getItems()[0]);
		}
		else {
			logger.debug("No Application was found with this name " + "daonbank");
		}

		request.setDescription("OpenAM has Requested an Authentication.");
		request.setType("IX");
		request.setAuthenticationRequestId(UUID.randomUUID().toString());
		//TODO This should probably also be configuration for administrator to choose
		request.setPushNotificationType(TransactionPushNotificationTypeEnum.VERIFY_WITH_CONFIRMATION);
		AuthenticationRequestRepository authenticationRequestRepo = tenantRepoFactory.getAuthenticationRequestRepo();
		try {
			request = authenticationRequestRepo.create(request);
		} catch (IdxRestException e) {
			throw new NodeProcessException(e);
		}
		logger.debug("Added an authentication request, - authRequestId: {}" + request.getId());
		return request.getHref();
	}

	private User findUser(String userId, TenantRepoFactory tenantRepoFactory) throws NodeProcessException {
    	UserRepository userRepo = tenantRepoFactory.getUserRepo();
    	UserQueryHolder holder = new UserQueryHolder();
    	holder.getSearchSpec().setUserId(userId);
		UserCollection userCollection = null;
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

}
