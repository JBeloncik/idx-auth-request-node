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

import static org.forgerock.openam.auth.node.api.Action.goTo;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.google.inject.assistedinject.Assisted;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.credentialsProviders.EncryptedKeyPropFileCredentialsProvider;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.repositories.AuthenticationRequestRepository;
import com.sun.identity.idm.AMIdentity;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.List;
import javax.inject.Inject;
import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import com.daon.identityx.fido.IdentityXServices;

/**
 * A node that checks to see if zero-page login headers have specified username and shared key
 * for this request.
 */
@Node.Metadata(outcomeProvider  = IdxAuthStatusNode.IdxAuthStatusOutcomeProvider.class,
               configClass      = IdxAuthStatusNode.Config.class)
public class IdxAuthStatusNode implements Node {

  private static final String PENDING = "Pending";
  private static final String SUCCESS = "Success";
  private static final String FAILED = "Failed";
  private static final String EXPIRED = "Expired";
  //private static final String BUNDLE = IdxAuthStatusNode.class.getName().replace(".", "/");

    private final Config config;
    private final CoreWrapper coreWrapper;

    private final Logger logger = LoggerFactory.getLogger("amAuth");
    private final String IDX_HREF_KEY = "idx-auth-ref-shared-state-key";

    /**
     * Configuration for the node.
     */
    interface Config {

    }


    /**
     * Create the node.
     * @param config The service config.
     */
    @Inject
    public IdxAuthStatusNode(@Assisted Config config, CoreWrapper coreWrapper) {
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

        logger.debug("Connected to the IdentityX Server");
      } catch (Exception ex) {
        logger.error("An exception occurred connecting to the IX Server: " + ex );
      }


   //call API to check status. Return true, false or pending
    //get the authHref value from sharedState
      String authHref = context.sharedState.get(IDX_HREF_KEY).asString();
      if (authHref == null) {
        logger.error("Error: href not found in SharedState!");
        throw new NodeProcessException("Unable to authenticate - HREF not found!");
      }

      String status = getAuthenticationRequestStatus(authHref, tenantRepoFactory);
      if(status.equalsIgnoreCase("COMPLETED_SUCCESSFUL"))
		  {
			     return goTo(SUCCESS).replaceSharedState(context.sharedState.copy().put(USERNAME, username)).build();
		  }
      else if (status.equalsIgnoreCase("PENDING"))
      {
          return goTo(PENDING).replaceSharedState(context.sharedState.copy().put(USERNAME, username)).build();
      }
      else if (status.equalsIgnoreCase("EXPIRED"))
      {
          return goTo(EXPIRED).replaceSharedState(context.sharedState.copy().put(USERNAME, username)).build();
      }
		  else
		  {
			     return goTo(FAILED).build();
		  }

    }

    private String getAuthenticationRequestStatus(String authRequestHref, TenantRepoFactory tenantRepoFactory)
	  {
		    try {
			     AuthenticationRequest request = new AuthenticationRequest();
			     AuthenticationRequestRepository authenticationRequestRepo = tenantRepoFactory.getAuthenticationRequestRepo();
			     request = authenticationRequestRepo.get(authRequestHref);
           logger.debug("Retrieving an AuthenticationRequest with an HREF of " + authRequestHref);
			     return request.getStatus().toString();
		    } catch (IdxRestException ex) {
           logger.debug("An exception occurred while attempting to determine the status of the authentication request.  Exception: " + ex.getMessage());
		    }
		    return null;
	}



    /**
     * Defines the possible outcomes from this node.
     */
    public static class IdxAuthStatusOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            return ImmutableList.of(
                    new Outcome(SUCCESS, "Success"),
                    new Outcome(FAILED, "Failed"),
                    new Outcome(PENDING, "Pending"),
                    new Outcome(EXPIRED, "Expired"));
        }
    }

}
