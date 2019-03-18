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

import static com.daon.idxAuthRequestNode.IdxCommon.IDX_HREF_KEY;
import static com.daon.idxAuthRequestNode.IdxCommon.getTenantRepoFactory;
import static com.daon.idxAuthRequestNode.IdxCommon.objectMapper;

import com.daon.identityx.rest.model.def.PolicyStatusEnum;
import com.daon.identityx.rest.model.def.TransactionPushNotificationTypeEnum;
import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.daon.identityx.rest.model.pojo.User;
import com.google.inject.assistedinject.Assisted;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.collections.ApplicationCollection;
import com.identityx.clientSDK.collections.PolicyCollection;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.queryHolders.ApplicationQueryHolder;
import com.identityx.clientSDK.queryHolders.PolicyQueryHolder;
import com.identityx.clientSDK.repositories.ApplicationRepository;
import com.identityx.clientSDK.repositories.AuthenticationRequestRepository;
import com.identityx.clientSDK.repositories.PolicyRepository;
import com.sun.identity.sm.RequiredValueValidator;
import java.io.IOException;
import java.util.Optional;
import java.util.UUID;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.TextOutputCallback;

import org.apache.commons.lang.StringUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A node that initiates an authentication request to IdentityX
 */
@Node.Metadata(outcomeProvider  = SingleOutcomeNode.OutcomeProvider.class,
               configClass      = IdxAuthRequestNode.Config.class)
public class IdxAuthRequestNode extends SingleOutcomeNode {

	/**
	 * Configuration for the node.
	 */
	public interface Config {
		/**
		 * the IdentityX policy which should be used for authentication
		 * @return the policy name
		 */
		@Attribute(order = 100, validators = {RequiredValueValidator.class})
		String policyName();

		/**
		 * the IdentityX application to be used
		 * @return the application Id
		 */
		@Attribute(order = 200, validators = {RequiredValueValidator.class})
		String applicationId();

		/**
		 * the IdenitityX request type (IX, FI)
		 * @return the request type
		 */
		@Attribute(order = 300, validators = {RequiredValueValidator.class})
		default boolean isFidoRequest() {
			return true;
		}

		/**
		 * option to send push notifications
		 * @return true or false
		 */
		@Attribute(order = 400, validators = {RequiredValueValidator.class})
		default boolean sendPushNotification() {
			return true;
		}
	}

	private final Config config;
	private final Logger logger = LoggerFactory.getLogger("amAuth");

    /**
     * Create the node.
	 */
    @Inject
    public IdxAuthRequestNode(@Assisted Config config) {
		this.config = config;
	}

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
    	User user;
		try {
			user = objectMapper.readValue(context.sharedState.get("Daon_User").asString(), User.class);
		} catch (IOException e) {
			logger.error("Can't find user in SharedState");
			throw new NodeProcessException(e);
		}

		TenantRepoFactory tenantRepoFactory = getTenantRepoFactory(context);
		logger.debug("Connected to the IdentityX Server");

		String authHref = generateAuthenticationRequest(user, config.policyName(), tenantRepoFactory);
		logger.debug("Auth href: " + authHref);

    	//Place the href value in sharedState
    	logger.debug("Setting auth URL in shared state...");
		JsonValue newState = context.sharedState.copy().put(IDX_HREF_KEY, authHref);

    	return goToNext().replaceSharedState(newState).build();
    }

	private String generateAuthenticationRequest(User user, String policyName, TenantRepoFactory
		   tenantRepoFactory) throws NodeProcessException {

		AuthenticationRequest request = new AuthenticationRequest();
		if (user == null) {
			String error = "Error retrieving user";
			logger.error(error);
			throw new NodeProcessException(error);
		}
		else {
			logger.debug("User found with ID " + user.getUserId());
			request.setUser(user);
		}

		PolicyQueryHolder holder = new PolicyQueryHolder();
		holder.getSearchSpec().setPolicyId(policyName);
		holder.getSearchSpec().setStatus(PolicyStatusEnum.ACTIVE);
		PolicyRepository policyRepo = tenantRepoFactory.getPolicyRepo();
		PolicyCollection policyCollection;
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
			logger.error("Could not find an active policy with the PolicyId: " + policyName);
			throw new NodeProcessException("Could not find an active policy with the PolicyId: " + policyName);
		}

		String appId = config.applicationId();
		ApplicationRepository applicationRepo = tenantRepoFactory.getApplicationRepo();
		ApplicationQueryHolder applicationQueryHolder = new ApplicationQueryHolder();
		applicationQueryHolder.getSearchSpec().setApplicationId(appId);
		ApplicationCollection applicationCollection;
		try {
			applicationCollection = applicationRepo.list(applicationQueryHolder);
		} catch (IdxRestException e) {
			throw new NodeProcessException(e);
		}

		if (applicationCollection.getItems().length > 0) {
			request.setApplication(applicationCollection.getItems()[0]);
		}
		else {
			logger.debug("No Application was found with this name " + appId);
			throw new NodeProcessException("No Application was found with this name " + appId);
		}

		request.setDescription("OpenAM has Requested an Authentication.");

		String txnRequestType = "FI";
		if (!config.isFidoRequest()) {
			txnRequestType = "IX";
		}
		request.setType(txnRequestType);
		request.setOneTimePasswordEnabled(false);
		request.setAuthenticationRequestId(UUID.randomUUID().toString());

		if (config.sendPushNotification()) {
			request.setPushNotificationType(TransactionPushNotificationTypeEnum.VERIFY_WITH_CONFIRMATION);
		}

		AuthenticationRequestRepository authenticationRequestRepo = tenantRepoFactory.getAuthenticationRequestRepo();
		try {
			request = authenticationRequestRepo.create(request);
		} catch (IdxRestException e) {
			logger.debug("Error creating authentication request for user: " + user.getUserId());
			throw new NodeProcessException(e);
		}
		logger.debug("Added an authentication request, - authRequestId: {}" + request.getId());
		return request.getHref();
	}


}
