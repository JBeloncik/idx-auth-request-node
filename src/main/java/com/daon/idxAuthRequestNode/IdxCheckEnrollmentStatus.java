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

import static com.daon.idxAuthRequestNode.IdxCommon.findUser;

import com.daon.identityx.rest.model.pojo.User;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.inject.assistedinject.Assisted;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.sun.identity.sm.RequiredValueValidator;
import javax.inject.Inject;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.openam.auth.node.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


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
        @Password
        char[] jksPassword();

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
        @Password
        char[] keyPassword();

    }

    private final Config config;
    private final Logger logger = LoggerFactory.getLogger("amAuth");

    @Inject
    public IdxCheckEnrollmentStatus(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        String username = context.sharedState.get(SharedStateConstants.USERNAME).asString();

        String keyStore = config.pathToKeyStore();
        String credentialProperties = config.pathToCredentialProperties();
        String jksPassword = String.valueOf(config.jksPassword());
        String keyAlias = config.keyAlias();
        String keyPassword = String.valueOf(config.keyPassword());

        TenantRepoFactory tenantRepoFactory = null;
        try {
            tenantRepoFactory = IdxTenantRepoFactorySingleton.getInstance(keyStore, jksPassword, credentialProperties,
                    keyAlias, keyPassword).tenantRepoFactory;
        } catch (IdxRestException e) {
            logger.debug("An exception occurred using the tenantRepoFactorySingleton");
            throw new NodeProcessException("Error using tenantRepoFactorySingleton");
        }

        logger.debug("Connected to the IdentityX Server");


        //set all config params in SharedState
        JsonValue newState = context.sharedState.copy();
        newState.put("IdxPathToKeyStore", keyStore);
        newState.put("IdxPathToCredentialProperties", credentialProperties);
        newState.put("IdxJksPassword", jksPassword);
        newState.put("IdxKeyAlias", keyAlias);
        newState.put("IdxKeyPassword", keyPassword);

        User user = findUser(username, tenantRepoFactory);
        if (user == null) {
            logger.debug("User with ID " + username + " not found in IdentityX!");
            return goTo(false).replaceSharedState(newState).build();
        }

        logger.debug("User found with ID " + username);
        try {
            newState.put("Daon_User", IdxCommon.objectMapper.writeValueAsString(user));
        } catch (JsonProcessingException e) {
            logger.error("Unable to write the user object as string");
        }


        return goTo(true).replaceSharedState(newState).build();
    }



}
