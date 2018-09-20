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
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A node that checks to see if zero-page login headers have specified username and shared key
 * for this request.
 */
@Node.Metadata(outcomeProvider  = IdxAuthStatusNode.IdxAuthStatusOutcomeProvider.class,
        configClass      = IdxAuthStatusNode.Config.class)
public class IdxCheckEnrollmentStatus extends AbstractDecisionNode {


    private final Logger logger = LoggerFactory.getLogger("amAuth");

    /**
     * Configuration for the node.
     */
    interface Config {

    }

    @Inject
    public IdxCheckEnrollmentStatus() {

    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        return goTo(isEnrolled(context.sharedState)).build();
    }

    private boolean isEnrolled(JsonValue sharedState) {
        //TODO Check if the user is enrolled in identityX
        return true;
    }


}
