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

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.openam.utils.StringUtils;
import com.daon.identityx.rest.model.pojo.User;
import com.google.inject.assistedinject.Assisted;
import com.identityx.clientSDK.TenantRepoFactory;
import com.sun.identity.sm.RequiredValueValidator;

import javax.inject.Inject;


/**
 * A node that checks to see if a provided username is enrolled in IdentityX
 *
 * Note on the userId value:
 * By default, the node will assume the provided username is the userId value from ForgeRock.
 * If the implementation needs to use a different value for the IdentityX userId, a custom
 * node will need to be inserted before this one to provide such mapping. Config values in
 * this node will allow the administrator to define which value in sharedState to use for the
 * IdentityX userId.
 *
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
        configClass      = IdxCheckEnrollmentStatus.Config.class, tags = {"mfa", "multi-factor authentication"})
public class IdxCheckEnrollmentStatus extends AbstractDecisionNode {

    /**
     * Configuration for the node.
     */
    public interface Config {

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

        /**
         * the attribute in sharedState to use for IdentityX userId
         * @return the userIdAttribute
         */
        @Attribute(order = 600)
        String userIdAttribute();

    }

    private final Config config;
    private static LoggerWrapper logger = new LoggerWrapper();

    @Inject
    public IdxCheckEnrollmentStatus(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        String userIdAttribute;
        //Check for the userIdAttribute in sharedState
        //If it is defined, we should use it instead of the AM USERNAME
        if (StringUtils.isBlank(config.userIdAttribute())) {
            userIdAttribute =  SharedStateConstants.USERNAME;
        } else {
            userIdAttribute = config.userIdAttribute();
        }

        JsonValue usernameJson = context.sharedState.get(userIdAttribute);

        if (usernameJson.isNull() || StringUtils.isBlank(usernameJson.asString())) {
            throw new NodeProcessException("Username attribute " + userIdAttribute + " is either null or empty");
        }

        String username = usernameJson.asString();

        String keyStore = config.pathToKeyStore();
        String credentialProperties = config.pathToCredentialProperties();
        String jksPassword = String.valueOf(config.jksPassword());
        String keyAlias = config.keyAlias();
        String keyPassword = String.valueOf(config.keyPassword());
        
        logger.debug("IdxCheckEnrollmentStatus::Configuration[PathToKeyStore={}, PathToCredentialProperties={}, KeyAlias={}]", keyStore, credentialProperties, keyAlias);

        TenantRepoFactory tenantRepoFactory = IdxTenantRepoFactorySingleton.getInstance(keyStore, jksPassword, credentialProperties, keyAlias, keyPassword).tenantRepoFactory;        

        //Set all config params in SharedState
        JsonValue newState = context.sharedState.copy();
        
        newState.put("IdxPathToKeyStore", keyStore);
        newState.put("IdxPathToCredentialProperties", credentialProperties);
        newState.put("IdxJksPassword", jksPassword);
        newState.put("IdxKeyAlias", keyAlias);
        newState.put("IdxKeyPassword", keyPassword);
        newState.put("IdxKeyUserName", username);

        User user = findUser(username, tenantRepoFactory);
        
        if (user == null) {
            logger.error("FATAL: UserID=[{}] not found in IdentityX", username);
            return goTo(false).replaceSharedState(newState).build();
        }
        
        logger.debug("Connected to the IdentityX Server @ [{}]", IdxCommon.getServerName(user.getHref()));
        logger.debug("User found with ID {}", username);
        
        newState.put(IdxCommon.IDX_USER_HREF_KEY, user.getHref());
        newState.put(IdxCommon.IDX_USER_INTERNAL_ID_KEY, user.getId());
		newState.put(IdxCommon.IDX_USER_ID_KEY, user.getUserId());
		
		logger.debug("Added to SharedState - User Id=[{}] UserId=[{}] Href=[{}]", user.getId(), user.getUserId(), user.getHref());

        return goTo(true).replaceSharedState(newState).build();
    }
}
