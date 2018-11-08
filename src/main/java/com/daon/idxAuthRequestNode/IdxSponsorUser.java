package com.daon.idxAuthRequestNode;

import static org.forgerock.openam.auth.node.api.Action.send;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.sm.RequiredValueValidator;
import java.util.Arrays;
import java.util.Optional;
import javax.inject.Inject;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.authentication.callbacks.PollingWaitCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
        configClass      = IdxSponsorUser.Config.class)
public class IdxSponsorUser extends AbstractDecisionNode {

    /**
     * Configuration for the node.
     */
    interface Config {

        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        int pollingWaitInterval();

        @Attribute(order = 200, validators = {RequiredValueValidator.class})
        int numberOfTimesToPoll();

    }

    private final Config config;
    private final Logger logger = LoggerFactory.getLogger("amAuth");
    private final String IDX_QR_KEY = "idx-qr-key";
    private final String IDX_POLL_TIMES = "idx-poll-times-remaining";



    /**
     * Create the node.
     * @param config The service config.
     */
    @Inject
    public IdxSponsorUser(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) {
        JsonValue sharedState = context.sharedState;
        Optional<ScriptTextOutputCallback> scriptTextOutputCallback = context.getCallback(ScriptTextOutputCallback
                 .class);
        String qrText;

        if (!sharedState.isDefined(IDX_QR_KEY) || !scriptTextOutputCallback.isPresent() || !scriptTextOutputCallback
                .get().getMessage().equals(sharedState.get(IDX_QR_KEY).asString())) {

            if (logger.isDebugEnabled()) {
                logger.debug("Entering into Sponsor User for the first time for user: " + sharedState.get
                        (SharedStateConstants.USERNAME).asString());
            }

            sharedState.put(IDX_POLL_TIMES, config.numberOfTimesToPoll());
            qrText = getQRText(sharedState);
            return buildResponse(sharedState, qrText);

        }
        if (isEnrolled(sharedState)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Enrollment Successful for: " + sharedState.get
                        (SharedStateConstants.USERNAME).asString());
            }
            // If enrollment is successful send user to next node
            return goTo(true).build();
        }

        // Build the callbacks and decrement from our configured number of poll times
        return buildResponse(sharedState, sharedState.get(IDX_QR_KEY).asString());



    }

    private Action buildResponse(JsonValue sharedState, String qrJavaScript) {
        Integer pollTimesRemaining = sharedState.get(IDX_POLL_TIMES).asInteger();
        if (pollTimesRemaining == 0) {
            // If number of times remaining to poll is 0, send user to false
            return goTo(false).replaceSharedState(sharedState).build();
        }
        sharedState.put(IDX_POLL_TIMES, pollTimesRemaining - 1);
        sharedState.put(IDX_QR_KEY, qrJavaScript);
        return send(Arrays.asList(new ScriptTextOutputCallback(qrJavaScript), new PollingWaitCallback(Integer
                .toString(config.pollingWaitInterval()), "Waiting for Response"))).replaceSharedState(sharedState)
                .build();
    }

    private String getQRText(JsonValue sharedState) {
        //TODO Get the QRText from IdentityX

        //testing only
        return "iVBORw0KGgoAAAANSUhEUgAAAH0AAAB9AQAAAACn+1GIAAAA8klEQVR42u3VsQ2EMAwFUKMUdLBAJNZI" +
                "l5lY4AgLhJXoskYkLwBdCoTPXHFAFae7k0iFXmGsHxuA7ifBAz8LDhSlzgO0YpgIvYHG8oMUPCAl3I0qAgfQFMJ6vLkAuN" +
                "Mx6det9QxwHt7gPaAM8FngKEBicBCruVuDHsRA1HmrxmvRHCx1bCy3ubVioKSHgFP65pGHHfjgfuaRB2+2inAKSHKo+WJ1" +
                "H84aAqBxjn3aCoDbrCM3S2I47orHJ5EceIIm3jmjWzHwnO41p77J4bNAmpMfisCqy2jLwMQhXD8GGeBOncWRCuDYOYtriK" +
                "0Ynl/BH8AbsuBdeh1MqsIAAAAASUVORK5CYII=";
    }

    private boolean isEnrolled(JsonValue sharedState) {
        if (logger.isDebugEnabled()) {
            logger.debug("Checking Enrollment Status for: " + sharedState.get
                    (SharedStateConstants.USERNAME).asString());
        }
        //TODO Get the enrollment status from Identity X
        return true;
    }


}