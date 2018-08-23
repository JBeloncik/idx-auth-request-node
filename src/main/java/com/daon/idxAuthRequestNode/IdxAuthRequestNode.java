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
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
               configClass      = IdxAuthRequestNode.Config.class)
public class IdxAuthRequestNode extends AbstractDecisionNode {

    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "IdxAuthRequestNode";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);

    private final Logger logger = LoggerFactory.getLogger("amAuth");

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100)
        default String usernameHeader() {
            return "X-OpenAM-Username";
        }

        @Attribute(order = 200)
        default String passwordHeader() {
            return "X-OpenAM-Password";
        }

        @Attribute(order = 300)
        default String secretKey() {
            return "secretKey";
        }
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
      String secret = config.secretKey();
      String password = context.transientState.get(SharedStateConstants.PASSWORD).asString();
      String username = context.sharedState.get(SharedStateConstants.USERNAME).asString();
      AMIdentity userIdentity = coreWrapper.getIdentity(username, context.sharedState.get(REALM).asString());

/*  Original working simple code
 *** This simply checks the username is active and checks the password against the configured value for secretKey

      try {
          if (secret.equals(password) && userIdentity != null && userIdentity.isExists() && userIdentity.isActive()) {
              return goTo(true).replaceSharedState(context.sharedState.copy().put(USERNAME, username)).build();
          }
      } catch (IdRepoException e) {
          debug.error("[" + DEBUG_FILE + "]: " + "Error locating user '{}' ", e);
      } catch (SSOException e) {
          debug.error("[" + DEBUG_FILE + "]: " + "Error locating user '{}' ", e);
      }
      return goTo(false).build();
*/
      //Idx code to call the new methods below
/*
          TenantRepoFactory tenantRepoFactory = null;
    		try {
    				InputStream keyStore = new FileInputStream(new File("IdentityXKeyWrapper.jks"));
    				InputStream credenitalsProperties = new FileInputStream(new File("credental.properties"));
    			EncryptedKeyPropFileCredentialsProvider provider = new EncryptedKeyPropFileCredentialsProvider(
    					keyStore,
    					"password",
    					credenitalsProperties,
    					"identityxCert",
    					"password");
    			tenantRepoFactory = new TenantRepoFactory(provider);

    			System.out.println("Connected to the IdentityX Server");
          debug.message("Connected to Idx server");

    		} catch (Exception e) {
    			System.out.println("An exception occurred connecting to the IX Server");

          debug.error("[" + DEBUG_FILE + "]: " + "An exception occurred connecting to the IX Server ", e);
    		}

       try {
         //String authHref = generateAuthenticationRequest(username, "login", tenantRepoFactory);
       } catch (Exception e) {
         debug.error("[" + DEBUG_FILE + "]: " + "Error generating transaction ", e);

       }



*/


//simple test to call private method
        if (testPassword(password)) {
          return goTo(true).replaceSharedState(context.sharedState.copy().put(USERNAME, username)).build();
        } else {
          return goTo(false).build();
        }

    }



//This code works!
	private boolean testPassword(String pass) throws NodeProcessException {

        String mySecret = "jbtest";

        if (pass.equals(mySecret)) {
            return true;
        } else {
          logger.error("Password is not correct. Try jbtest");
          throw new NodeProcessException("Unable to authenticate");
        }


	}


  private User findUser(String userId, TenantRepoFactory tenantRepoFactory) throws NodeProcessException {

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
  			throw new NodeProcessException("More than one user with the same UserId!!!!");
  		}

    } catch (IdxRestException e) {
      logger.error("exception getting user collection");
    }

    return null;
	}

}
