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

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.UUID;

//import com.daon.identityx.fido.IdentityXServices;
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

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.json.JsonValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.InvalidPasswordException;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;


import javax.inject.Inject;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

/**
 * A node that checks to see if zero-page login headers have specified username and shared key
 * for this request.
 */
@Node.Metadata(outcomeProvider  = SingleOutcomeNode.OutcomeProvider.class,
               configClass      = IdxAuthRequestNode.Config.class)
public class IdxAuthRequestNode extends SingleOutcomeNode {

    private final Config config;
    private final CoreWrapper coreWrapper;
    //private final static String DEBUG_FILE = "IdxAuthRequestNode";
    //protected Debug debug = Debug.getInstance(DEBUG_FILE);

    private final Logger logger = LoggerFactory.getLogger("amAuth");

    private final String IDX_HREF_KEY = "idx-auth-ref-shared-state-key";

    /**
     * Configuration for the node.
     */
    public interface Config {

    }


    /**
     * Create the node.
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public IdxAuthRequestNode(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

      String username = context.sharedState.get(SharedStateConstants.USERNAME).asString();
      AMIdentity userIdentity = coreWrapper.getIdentity(username, context.sharedState.get(REALM).asString());



        TenantRepoFactory tenantRepoFactory = null;
		try {
				InputStream keyStore = new FileInputStream(new File("home/ubuntu/tomcat/daonconfig/IdentityXKeyWrapper.jks"));
				InputStream credenitalsProperties = new FileInputStream(new File("home/ubuntu/tomcat/daonconfig/credential.properties"));
			EncryptedKeyPropFileCredentialsProvider provider = new EncryptedKeyPropFileCredentialsProvider(
					keyStore,
					"password",
					credenitalsProperties,
					"identityxCert",
					"password");
			tenantRepoFactory = new TenantRepoFactory(provider);

			System.out.println("Connected to the IdentityX Server");
      logger.debug("Connected to the IdentityX Server");
		} catch (Exception ex) {
			System.out.println("An exception occurred connecting to the IX Server");
      logger.debug("An exception occurred connecting to the IX Server: " + ex );
		}

		String authHref = generateAuthenticationRequest(username, "login", tenantRepoFactory);
		logger.debug("Auth href: " + authHref);

    //Place the href value in sharedState
    logger.debug("Setting auth URL in shared state...");
    JsonValue newState = context.sharedState.copy().put(IDX_HREF_KEY, authHref);

    return goToNext().replaceSharedState(newState).build();
    }


  private String generateAuthenticationRequest(String userId, String policyName, TenantRepoFactory tenantRepoFactory)
	{
		try {
			AuthenticationRequest request = new AuthenticationRequest();
			if ((userId != null) && (userId.length() > 0))
			{
				User user;
				user = this.findUser(userId, tenantRepoFactory);
				if (user == null) {
          logger.error("Error retrieving user");
				}
				else
				{
          logger.debug("User found with ID " + userId);
					request.setUser(user);
				}
			}

			PolicyQueryHolder holder = new PolicyQueryHolder();
			holder.getSearchSpec().setPolicyId(policyName);
			holder.getSearchSpec().setStatus(PolicyStatusEnum.ACTIVE);
			PolicyRepository policyRepo = tenantRepoFactory.getPolicyRepo();
			PolicyCollection policyCollection = policyRepo.list(holder);
			if(policyCollection.getItems().length > 0)
			{
				logger.debug("SETTING POLICY on AUTHENTICATON REQUEST");
				request.setPolicy(policyCollection.getItems()[0]);
			}
			else
			{
				logger.debug("Could not find an active policy with the PolicyId: " + policyName);
			}


			ApplicationRepository applicationRepo = tenantRepoFactory.getApplicationRepo();
			ApplicationQueryHolder applicationQueryHolder = new ApplicationQueryHolder();
			applicationQueryHolder.getSearchSpec().setApplicationId("daonbank");
			ApplicationCollection applicationCollection = applicationRepo.list(applicationQueryHolder);

			if(applicationCollection.getItems().length > 0)
			{
				request.setApplication(applicationCollection.getItems()[0]);
			}
			else
			{
				logger.debug("No Application was found with this name " + "daonbank");
			}
			request.setDescription("OpenAM has Requested an Authentication.");
			request.setType("IX");
			request.setAuthenticationRequestId(UUID.randomUUID().toString());
			request.setPushNotificationType(TransactionPushNotificationTypeEnum.VERIFY_WITH_CONFIRMATION);
			AuthenticationRequestRepository authenticationRequestRepo = tenantRepoFactory.getAuthenticationRequestRepo();
			request = authenticationRequestRepo.create(request);

      logger.error("Added an authentication request, - authRequestId: {}" + request.getId());
			return request.getHref();
		} catch (IdxRestException ex) {
      logger.error("An exception occurred while attempting to create an authentication request. Exception: " + ex.getMessage());
		}
		return null;
	}

  private User findUser(String userId, TenantRepoFactory tenantRepoFactory) {

		UserRepository userRepo = tenantRepoFactory.getUserRepo();
		UserQueryHolder holder = new UserQueryHolder();
		holder.getSearchSpec().setUserId(userId);
    try {
      UserCollection userCollection = userRepo.list(holder);

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
  			logger.debug("More than one user with the same UserId!!!!");
        return null;
  		}

    } catch (IdxRestException e) {
      logger.error("exception getting user collection");
    }

    return null;
	}

}
