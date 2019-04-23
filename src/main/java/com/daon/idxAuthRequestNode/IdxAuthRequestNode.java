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
import java.util.UUID;
import javax.inject.Inject;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.utils.StringUtils;
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
		 * the IdenitityX policy which should be used for authentication
		 * @return the policy name
		 */
		@Attribute(order = 100, validators = {RequiredValueValidator.class})
		String policyName();

		/**
		 * the IdenitityX application to be used
		 * @return the application Id
		 */
		@Attribute(order = 200, validators = {RequiredValueValidator.class})
		String applicationId();

		/**
		 * the IdentityX request type (IX, FI)
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

		/**
		 * the default transaction description
		 * @return the defaultTransactionDescriptionText
		 */
		@Attribute(order = 500, validators = {RequiredValueValidator.class})
		default String defaultTransactionDescriptionText() {
			return "ForgeRock Authentication Request";
		}

		/**
		 * the sharedState attribute which provides the transaction description text
		 * @return the transactionDescriptionAttribute
		 */
		@Attribute(order = 600)
		default String transactionDescriptionAttribute() {
			return "idx-transaction-description-text";
		}

		/**
		 * the source of secure transaction data
		 */
		@Attribute(order = 700)
		default SecureTransactionSource secureTransactionSource() {
			return SecureTransactionSource.NONE;
		}

		/**
		 * the type of secure transaction data. Either text/plain or image/png
		 */
		@Attribute(order = 800)
		default SecureTransactionContentType secureTransactionContentType() {
			return SecureTransactionContentType.TEXT;
		}

		/**
		 * the secure transaction data - text or base64 encoded png
		 * @return the secureTransactionData
		 */
		@Attribute(order = 900)
		default String secureTransactionData() {
			return "secure transaction data";
		}

		/**
		 * the sharedState attribute which provides secure transaction content type
		 * @return the secureTransactionContentTypeAttribute
		 */
		@Attribute(order = 1000)
		default String secureTransactionContentTypeAttribute() {
			return "idx-secure-content-type";
		}

		/**
		 * the sharedState attribute which provides secure transaction text data
		 * @return the secureTransactionDataAttribute
		 */
		@Attribute(order = 1100)
		default String secureTransactionDataAttribute() {
			return "idx-secure-content-data";
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

		String authHref = generateAuthenticationRequest(user, config.policyName(), tenantRepoFactory,
				context.sharedState);
		logger.debug("Auth href: " + authHref);

    	//Place the href value in sharedState
    	logger.debug("Setting auth URL in shared state...");
		String IDX_HREF_KEY = "idx-auth-ref-shared-state-key";
		JsonValue newState = context.sharedState.copy().put(IDX_HREF_KEY, authHref);

    	return goToNext().replaceSharedState(newState).build();
    }

	private String generateAuthenticationRequest(User user, String policyName, TenantRepoFactory
		   tenantRepoFactory, JsonValue sharedState) throws NodeProcessException {

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

		//Set the transaction description text from either sharedState or the node config
		String transactionDescriptionText = config.defaultTransactionDescriptionText();

		//Check sharedState for the descriptionText
		String txnRequestAttribute = config.transactionDescriptionAttribute();
		if (!StringUtils.isBlank(txnRequestAttribute)) {
			String textFromSharedState = sharedState.get(txnRequestAttribute).asString();
			if (!StringUtils.isBlank(textFromSharedState)) {
				transactionDescriptionText = textFromSharedState;
			}
		}
		request.setDescription(transactionDescriptionText);

		String txnRequestType = "FI";
		if (!config.isFidoRequest()) {
			txnRequestType = "IX";
		}
		request.setType(txnRequestType);
		request.setOneTimePasswordEnabled(false);
		request.setAuthenticationRequestId(UUID.randomUUID().toString());

		//Secure transaction content
		//Only valid for Fido transactions
		if (config.isFidoRequest() && (config.secureTransactionSource() != SecureTransactionSource.NONE)) {

			String secureTxnType = "text/plain";
			String secureTxnData = "default secure transaction data";

			switch(config.secureTransactionSource()) {
				case CONFIG:
					secureTxnData = config.secureTransactionData();
					if (config.secureTransactionContentType() == SecureTransactionContentType.IMAGE) {
						secureTxnType = "image/png";
					}
					break;
				case SHAREDSTATE:
					String secureContentTypeAttr = config.secureTransactionContentTypeAttribute();
					String secureContentAttr = config.secureTransactionDataAttribute();
					if (StringUtils.isEmpty(secureContentTypeAttr)) {
						logger.debug("secureTransactionContentTypeAttribute is empty! Using default text/plain");
					} else {
						if (sharedState.get(secureContentTypeAttr).asString().equals("image/png")) {
							secureTxnType = "image/png";
						}
					}

					if (StringUtils.isEmpty(secureContentAttr)) {
						logger.debug("secureTransactionDataAttribute is empty! Using default text.");
					} else {
						if (!StringUtils.isEmpty(sharedState.get(secureContentAttr).asString())) {
							secureTxnData = sharedState.get(secureContentAttr).asString();
							logger.debug("Secure data from sharedState: " + secureTxnData);
						}
					}
					break;
			}

			switch (secureTxnType) {
				case "image/png":
					request.setSecureTransactionContentType("image/png");
					request.setSecureImageTransactionContent(secureTxnData);
					break;
				default:
					request.setSecureTransactionContentType("text/plain");
					request.setSecureTextTransactionContent(secureTxnData);
					break;

			}

		}

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
		logger.debug("Added an authentication request, - authRequestId: " + request.getId());
		return request.getHref();
	}

	/**
	 * enum definition for secure transaction data configuration
	 */
	public enum SecureTransactionSource {
		/** None. Do not use secure transactions details. **/
		NONE,
		/** Set in config by admin **/
		CONFIG,
		/** Set in SharedState **/
		SHAREDSTATE
	}

	/**
	 * enum definition for secure transaction content type
	 */
	public enum SecureTransactionContentType {
		/** text/plain **/
		TEXT,
		/** image/png **/
		IMAGE
	}

}
