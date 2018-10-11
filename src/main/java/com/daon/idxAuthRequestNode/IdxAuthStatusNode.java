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
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.credentialsProviders.EncryptedKeyPropFileCredentialsProvider;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.repositories.AuthenticationRequestRepository;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.List;
import javax.inject.Inject;
import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A node that checks user authentication status in IdentityX
 */
@Node.Metadata(outcomeProvider  = IdxAuthStatusNode.IdxAuthStatusOutcomeProvider.class,
               configClass      = IdxAuthStatusNode.Config.class)
public class IdxAuthStatusNode implements Node {

    private static final String PENDING = "Pending";
    private static final String SUCCESS = "Success";
    private static final String FAILED = "Failed";
    private static final String EXPIRED = "Expired";

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
    public IdxAuthStatusNode() {
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        String username = context.sharedState.get(SharedStateConstants.USERNAME).asString();
        TenantRepoFactory tenantRepoFactory = null;
        try {
            //InputStream keyStore = new FileInputStream(new File("home/ubuntu/tomcat/daonconfig/IdentityXKeyWrapper" +
            //         ".jks"));
            //InputStream credenitalsProperties = new FileInputStream(new File
            //         ("home/ubuntu/tomcat/daonconfig/credential.properties"));
             //EncryptedKeyPropFileCredentialsProvider provider = new EncryptedKeyPropFileCredentialsProvider(keyStore,
             //        "password", credenitalsProperties, "identityxCert", "password");

            //Pull these config values from SharedState. They should have been set by the IdxCheckEnrollmentStatus node
            String pathToKeyStore = context.sharedState.get("IdxPathToKeyStore").asString();
            if (pathToKeyStore == null) {
                logger.error("Error: Path to JKS KeyStore not found in SharedState!");
                throw new NodeProcessException("Path to JKS KeyStore not found!");
            }
            InputStream keyStore = new FileInputStream(new File(pathToKeyStore));

            String pathToCredentialProperties = context.sharedState.get("IdxPathToCredentialProperties").asString();
            if (pathToCredentialProperties == null) {
                logger.error("Error: Path to credential.properties file not found in SharedState!");
                throw new NodeProcessException("Path to credential.properties file not found!");
            }
            InputStream credentialsProperties = new FileInputStream(new File(pathToCredentialProperties));

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
            EncryptedKeyPropFileCredentialsProvider provider = new EncryptedKeyPropFileCredentialsProvider(keyStore,
                    jksPassword, credentialsProperties, keyAlias, keyPassword);

             tenantRepoFactory = new TenantRepoFactory(provider);
             logger.debug("Connected to the IdentityX Server");
        } catch (Exception ex) {
            logger.error("An exception occurred connecting to the IX Server: " + ex );
            throw new NodeProcessException("Error creating tenant factory" + ex);
        }


    //call API to check status. Return true, false or pending
    //get the authHref value from sharedState
        String IDX_HREF_KEY = "idx-auth-ref-shared-state-key";
        String authHref = context.sharedState.get(IDX_HREF_KEY).asString();
      if (authHref == null) {
        logger.error("Error: href not found in SharedState!");
        throw new NodeProcessException("Unable to authenticate - HREF not found!");
      }

      String status = getAuthenticationRequestStatus(authHref, tenantRepoFactory);
      if(status.equalsIgnoreCase("COMPLETED_SUCCESSFUL")) {
          return goTo(SUCCESS).replaceSharedState(context.sharedState.copy().put(USERNAME, username)).build();
      }
      else if (status.equalsIgnoreCase("PENDING")) {
          return goTo(PENDING).replaceSharedState(context.sharedState.copy().put(USERNAME, username)).build();
      }
      else if (status.equalsIgnoreCase("EXPIRED")) {
          return goTo(EXPIRED).replaceSharedState(context.sharedState.copy().put(USERNAME, username)).build();
      }
      else {
         return goTo(FAILED).build();
      }

    }

    private String getAuthenticationRequestStatus(String authRequestHref, TenantRepoFactory tenantRepoFactory) throws
            NodeProcessException {
        try {
            AuthenticationRequest request;
            AuthenticationRequestRepository authenticationRequestRepo = tenantRepoFactory.getAuthenticationRequestRepo();
            request = authenticationRequestRepo.get(authRequestHref);
            logger.debug("Retrieving an AuthenticationRequest with an HREF of " + authRequestHref);
            return request.getStatus().toString();
        } catch (IdxRestException ex) {
            logger.debug("An exception occurred while attempting to determine the status of the authentication request.  Exception: " + ex.getMessage());
            throw new NodeProcessException(ex);
        }
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
