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
import static org.forgerock.openam.auth.node.api.Action.goTo;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.repositories.AuthenticationRequestRepository;
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;
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
    public interface Config {
    }


    /**
     * Create the node.
     */
    @Inject
    public IdxAuthStatusNode() {
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        //String username = context.sharedState.get(SharedStateConstants.USERNAME).asString();
        String username = context.sharedState.get("IdxKeyUserName").asString();
        if (username == null) {
            String errorMessage = "Error: IdxKeyUserName not found in sharedState! Make sure " +
                    "IdxCheckEnrollmentStatus node is in the tree!";
            logger.error(errorMessage);
            throw new NodeProcessException(errorMessage);
        }

        TenantRepoFactory tenantRepoFactory = getTenantRepoFactory(context);
        logger.debug("Connected to the IdentityX Server");

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
            return goTo(SUCCESS).build();
        }
        else if (status.equalsIgnoreCase("PENDING")) {
            return goTo(PENDING).build();
        }
        else if (status.equalsIgnoreCase("EXPIRED")) {
            return goTo(EXPIRED).build();
        }
        else {
            return goTo(FAILED).build();
        }
    }

    private String getAuthenticationRequestStatus(String authRequestHref, TenantRepoFactory tenantRepoFactory) throws
            NodeProcessException {

        AuthenticationRequestRepository authenticationRequestRepo = tenantRepoFactory.getAuthenticationRequestRepo();

        AuthenticationRequest request;
        try {
            request = authenticationRequestRepo.get(authRequestHref);
        } catch (IdxRestException e) {
            logger.debug("An exception occurred while attempting to determine the status of the authentication " +
                    "request.  Exception: " + e.getMessage());
            throw new NodeProcessException(e);
        }
        logger.debug("Retrieving an AuthenticationRequest with an HREF of " + authRequestHref);
        return request.getStatus().toString();
	}



    /**
     * Defines the possible outcomes from this node.
     */
    public static class IdxAuthStatusOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {

            List<Outcome> list = new ArrayList<>();

            list.add(new Outcome(SUCCESS, "Success"));
            list.add(new Outcome(FAILED, "Failed"));
            list.add(new Outcome(PENDING, "Pending"));
            list.add(new Outcome(EXPIRED, "Expired"));

            return list;
        }
    }

}
