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

import javax.inject.Inject;

import com.daon.identityx.rest.model.pojo.User;
import com.google.inject.assistedinject.Assisted;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.collections.UserCollection;
import com.identityx.clientSDK.credentialsProviders.EncryptedKeyPropFileCredentialsProvider;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.queryHolders.UserQueryHolder;
import com.identityx.clientSDK.repositories.UserRepository;
import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.sun.identity.sm.RequiredValueValidator;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.List;


/**
 * A node that checks to see if a provided username is enrolled in IdentityX
 *
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
        configClass      = IdxCheckEnrollmentStatus.Config.class)
public class IdxCheckEnrollmentStatus extends AbstractDecisionNode {

    /**
     * Configuration for the node.
     */
    interface Config {

        /**
         * the path to the jks keystore
         * @return the path to the jks keyStore
         */
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        String pathToKeyStore();

        /**
         * the path to the credential.properties file
         * @return the path to the credential.properties file
         */
        @Attribute(order = 200, validators = {RequiredValueValidator.class})
        String pathToCredentialProperties();

        /**
         * password for the jks keyStore
         * @return the jksPassword
         */
        @Attribute(order = 300, validators = {RequiredValueValidator.class})
        String jksPassword();

        /**
         * the key alias
         * @return the key alias
         */
        @Attribute(order = 400, validators = {RequiredValueValidator.class})
        String keyAlias();

        /**
         * password for the key
         * @return the keyPassword
         */
        @Attribute(order = 500, validators = {RequiredValueValidator.class})
        String keyPassword();

    }

    private final Config config;
    private final Logger logger = LoggerFactory.getLogger("amAuth");

    @Inject
    public IdxCheckEnrollmentStatus(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        boolean isUserEnrolled = isEnrolled(context.sharedState);

        //set all config params in SharedState
        JsonValue newState = context.sharedState.copy();
        newState.put("IdxPathToKeyStore", config.pathToKeyStore());
        newState.put("IdxPathToCredentialProperties", config.pathToCredentialProperties());
        newState.put("IdxJksPassword", config.jksPassword());
        newState.put("IdxKeyAlias", config.keyAlias());
        newState.put("IdxKeyPassword", config.keyPassword());

        return goTo(isUserEnrolled).replaceSharedState(newState).build();
    }

    private boolean isEnrolled(JsonValue sharedState) throws NodeProcessException {

        String username = sharedState.get(SharedStateConstants.USERNAME).asString();

        TenantRepoFactory tenantRepoFactory;
        try {

            InputStream keyStore = new FileInputStream(new File(config.pathToKeyStore()));
            InputStream credentialsProperties = new FileInputStream(new File(config.pathToCredentialProperties()));
            String jksPassword = config.jksPassword();
            String keyAlias = config.keyAlias();
            String keyPassword = config.keyPassword();

            EncryptedKeyPropFileCredentialsProvider provider = new EncryptedKeyPropFileCredentialsProvider(keyStore,
                    jksPassword, credentialsProperties, keyAlias, keyPassword);

            tenantRepoFactory = new TenantRepoFactory(provider);
            logger.debug("Connected to the IdentityX Server");
        } catch (Exception ex) {
            logger.debug("An exception occurred connecting to the IX Server: " + ex );
            throw new NodeProcessException("Error creating tenant factory" + ex);
        }

        User user = this.findUser(username, tenantRepoFactory);
        if (user == null) {
            logger.debug("User with ID " + username + " not found in IdentityX!");
            return false;
        }
        else {
            logger.debug("User found with ID " + username);
            return true;
        }

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
