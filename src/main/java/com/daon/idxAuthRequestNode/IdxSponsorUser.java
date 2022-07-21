package com.daon.idxAuthRequestNode;

import static com.daon.idxAuthRequestNode.IdxCommon.getTenantRepoFactory;
import static com.daon.idxAuthRequestNode.IdxSponsorUser.*;
import static org.forgerock.openam.auth.node.api.Action.goTo;
import static org.forgerock.openam.auth.node.api.Action.send;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.authentication.callbacks.PollingWaitCallback;
import org.forgerock.openam.utils.qr.ErrorCorrectionLevel;
import org.forgerock.openam.utils.qr.GenerationUtils;
import org.forgerock.util.i18n.PreferredLocales;
import com.daon.identityx.rest.model.def.PolicyStatusEnum;
import com.daon.identityx.rest.model.pojo.Policy.PolicyTypeEnum;
import com.daon.identityx.rest.model.pojo.Sponsorship;
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.collections.ApplicationCollection;
import com.identityx.clientSDK.collections.PolicyCollection;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.queryHolders.ApplicationQueryHolder;
import com.identityx.clientSDK.queryHolders.PolicyQueryHolder;
import com.identityx.clientSDK.repositories.ApplicationRepository;
import com.identityx.clientSDK.repositories.PolicyRepository;
import com.identityx.clientSDK.repositories.SponsorshipRepository;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.sm.RequiredValueValidator;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.UUID;
import javax.inject.Inject;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.TextOutputCallback;

@Node.Metadata(outcomeProvider = IdxSponsorOutcomeProvider.class, configClass = Config.class, tags = {"mfa", "multi-factor authentication"})
public class IdxSponsorUser implements Node {

    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * the IdentityX policy which should be used for enrollment
         * @return the policy name
         */
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        String enrollmentPolicyName();

        /**
         * the IdentityX application to be used
         * @return the application Id
         */
        @Attribute(order = 200, validators = {RequiredValueValidator.class})
        String applicationId();

        /**
         * The number of seconds to wait between polls
         * @return the int with number of whole seconds
         */
        @Attribute(order = 300, validators = {RequiredValueValidator.class})
        default int pollingWaitInterval() {
            return 10;
        }

        /**
         * The number of times to poll the status of the sponsorship request
         * @return the int with the number of times to poll
         */
        @Attribute(order = 400, validators = {RequiredValueValidator.class})
        default int numberOfTimesToPoll() {
            return 30;
        }

        /**
         * the message displayed to the user below the QR code
         * @return the messageText
         */
        @Attribute(order = 500, validators = {RequiredValueValidator.class})
        default String messageText() {
            return "Scan the QR code with your mobile app.";
        }

    }

    private final Config config;
    private static LoggerWrapper logger = new LoggerWrapper();
    private final String IDX_QR_KEY = "idx-qr-key";
    private final String IDX_POLL_TIMES = "idx-poll-times-remaining";
    private final String IDX_SPONSORSHIP_HREF = "idx-sponsorship-href";
    private static final String BUNDLE = IdxSponsorUser.class.getName();


    private String sponsorshipHref;

    /**
     * Create the node.
     * @param config The service config.
     */
    @Inject
    public IdxSponsorUser(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        JsonValue sharedState = context.sharedState;
        String qrText;

        //check for callback from the cancel button
        Optional<ConfirmationCallback> confirmationCallback = context.getCallback(ConfirmationCallback.class);

        if (confirmationCallback.isPresent()) {
            int index = confirmationCallback.get().getSelectedIndex();
            if (index == 0) {
                //user clicked cancel button
                logger.debug("User clicked cancel");
                sharedState.remove(IDX_POLL_TIMES);
                sharedState.remove(IDX_SPONSORSHIP_HREF);
                sharedState.remove(IDX_QR_KEY);
                return goTo(IdxSponsorOutcome.CANCEL.name()).replaceSharedState(sharedState).build();
            } else if (index == 1) {
                logger.debug("User clicked Email QR button");
                //the false output should be wired to a node which sends the email
                return goTo(IdxSponsorOutcome.EMAIL.name()).build();
            }
        }


        TenantRepoFactory tenantRepoFactory = getTenantRepoFactory(context);

        String username = sharedState.get("IdxKeyUserName").asString();
        if (username == null) {
            String errorMessage = "Error: IdxKeyUserName not found in sharedState! Make sure " +
                    "IdxCheckEnrollmentStatus node is in the tree!";
            logger.error(errorMessage);
            throw new NodeProcessException(errorMessage);
        }

        if (!sharedState.isDefined(IDX_QR_KEY)) {

           logger.debug("Entering into Sponsor User for the first time for user: [{}]", username);


            sharedState.put(IDX_POLL_TIMES, config.numberOfTimesToPoll());

            qrText = getQRText(tenantRepoFactory, username);

            sharedState.put(IDX_SPONSORSHIP_HREF, sponsorshipHref);

            String qrCallback = GenerationUtils.getQRCodeGenerationJavascript("callback_0", qrText,
                    20, ErrorCorrectionLevel.LOW);

            sharedState.put(IDX_QR_KEY, qrCallback);

            return buildResponse(sharedState);

        }
        if (isEnrolled(sharedState, tenantRepoFactory)) {
            logger.debug("Enrollment Successful for: [{}]", username);
            // If enrollment is successful send user to next node
            return goTo(IdxSponsorOutcome.TRUE.name()).build();
        }

        // Build the callbacks and decrement from our configured number of poll times
        return buildResponse(sharedState);

    }

    private Action buildResponse(JsonValue sharedState) {
        Integer pollTimesRemaining = sharedState.get(IDX_POLL_TIMES).asInteger();
        if (pollTimesRemaining == 0) {
            // If number of times remaining to poll is 0, send user to false
            sharedState.remove(IDX_POLL_TIMES);
            sharedState.remove(IDX_SPONSORSHIP_HREF);
            sharedState.remove(IDX_QR_KEY);
            return goTo(IdxSponsorOutcome.FALSE.name()).replaceSharedState(sharedState).build();
        }
        sharedState.put(IDX_POLL_TIMES, pollTimesRemaining - 1);

        ScriptTextOutputCallback qrCodeCallback = new ScriptTextOutputCallback(sharedState.get(IDX_QR_KEY).asString());

        TextOutputCallback textOutputCallback = new TextOutputCallback(TextOutputCallback.INFORMATION,
                config.messageText());

        String cancelString = "Cancel";
        String emailString = "Email QR Code";
        ConfirmationCallback confirmationCallback = new ConfirmationCallback(ConfirmationCallback.INFORMATION,
                new String[]{cancelString,emailString}, 0);
        confirmationCallback.setSelectedIndex(2);

        return send(Arrays.asList(textOutputCallback, qrCodeCallback,
                                  new PollingWaitCallback(Integer.toString(config.pollingWaitInterval() * 1000),
                           "Waiting for Enrollment to Complete..."), confirmationCallback))
                                .replaceSharedState(sharedState).build();
    }

    private String getQRText(TenantRepoFactory tenantRepoFactory, String userId)
        throws NodeProcessException {

        String appId = config.applicationId();
        String policyId = config.enrollmentPolicyName();

        //variable to hold the type of policy
        //IE is legacy IdentityX Enrollment, FR is FIDO Registration
        //IA and FA are authentication policies and should not be used here for registration
        PolicyTypeEnum policyType = PolicyTypeEnum.IE;

        //Create Sponsorship
        Sponsorship request = new Sponsorship();

        request.setUserId(userId);
        request.setType(Sponsorship.SponsorshipTypeEnum.USER);
        request.setRegistrationId(UUID.randomUUID().toString());

        PolicyQueryHolder holder = new PolicyQueryHolder();
        holder.getSearchSpec().setPolicyId(policyId);
        holder.getSearchSpec().setStatus(PolicyStatusEnum.ACTIVE);
        PolicyRepository policyRepo = tenantRepoFactory.getPolicyRepo();
        PolicyCollection policyCollection;
        try {
            policyCollection = policyRepo.list(holder);
        } catch (IdxRestException e) {
            throw new NodeProcessException(e);
        }
        if(policyCollection.getItems().length > 0) {
            logger.debug("Setting Policy On Sponsorship Request");
            request.setPolicy(policyCollection.getItems()[0]);

            policyType = policyCollection.getItems()[0].getType();
        }
        else {
            logger.error("Could not find an active policy with the PolicyId: " + config.enrollmentPolicyName());
            throw new NodeProcessException("Could not find an active policy with the PolicyId: " + config.enrollmentPolicyName());
        }



        ApplicationRepository applicationRepo = tenantRepoFactory.getApplicationRepo();
        ApplicationQueryHolder applicationQueryHolder = new ApplicationQueryHolder();
        applicationQueryHolder.getSearchSpec().setApplicationId(appId);
        ApplicationCollection applicationCollection;
        try {
            applicationCollection = applicationRepo.list(applicationQueryHolder);
        } catch (IdxRestException e) {
            throw new NodeProcessException(e);
        }

        if (applicationCollection.getItems().length > 0) {
            request.setApplication(applicationCollection.getItems()[0]);
        }
        else {
            logger.debug("No Application was found with this name " + appId);
            throw new NodeProcessException("No Application was found with this name " + appId);
        }

        SponsorshipRepository sponsorshipRepo = tenantRepoFactory.getSponsorshipRepo();
        try {
            request = sponsorshipRepo.create(request);
        }
        catch (IdxRestException e) {
            logger.debug("Error creating sponsorship for user: " + userId);
            throw new NodeProcessException(e);
        }

        //store the sponsorshipHref so we can query the status
        sponsorshipHref = request.getHref();

        logger.debug("Sponsorship created for userId " + userId);
        logger.debug("Sponsorship Code: " + request.getSponsorshipToken());

        //AM will build the QR code. Just need to provide the URL string
        String sponsorshipCodeUrl = "identityx://sponsor?SC=" + request.getSponsorshipToken();

        if (policyType == PolicyTypeEnum.IE) {
            String authGatewayURL = request.getAuthenticationGatewayURL();
            sponsorshipCodeUrl = "identityx://sponsor?SC=" + request.getSponsorshipToken() + "&KM=" +
                    authGatewayURL + "&TC=";
        }

        return sponsorshipCodeUrl;
    }

    private boolean isEnrolled(JsonValue sharedState, TenantRepoFactory tenantRepoFactory) throws NodeProcessException {

        logger.debug("Checking Sponsorship Status for: [{}]", sharedState.get("IdxKeyUserName").asString());

        String href = sharedState.get(IDX_SPONSORSHIP_HREF).toString().replaceAll("\"", "");
        logger.debug("Href: " + href);

        SponsorshipRepository sponsorshipRepo = tenantRepoFactory.getSponsorshipRepo();

        Sponsorship request;
        try {
            request = sponsorshipRepo.get(href);
        } catch (IdxRestException e) {
            logger.debug("An exception occurred while attempting to determine the status of the sponsorship " +
                    "request.  Exception: " + e.getMessage());
            throw new NodeProcessException(e);
        }

        //COMPLETED EXPIRED or PENDING
        switch (request.getStatus().toString()) {
            case "PENDING":
                logger.debug("Sponsorship status PENDING");
                return false;
            case "COMPLETED":
                logger.debug("Sponsorship status COMPLETED");
                return true;
            case "EXPIRED":
                logger.debug("Sponsorship status EXPIRED");
                return false;
            default:
                logger.debug("Sponsorship status not recognized");
                return false;
        }

    }

    /**
     * The possible outcomes for the IdxSponsor node.
     */
    public enum IdxSponsorOutcome {
        /**
         * Successful enrollment.
         */
        TRUE,
        /**
         * Failed enrollment.
         */
        FALSE,
        /**
         * The end user pressed the cancel button
         */
        CANCEL,
        /**
         * The end user pressed the email button
         */
        EMAIL
    }

    /**
     * Defines the possible outcomes from IdxSponsorUser node
     */
    public static class IdxSponsorOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
                                                                       IdxSponsorOutcomeProvider.class.getClassLoader());
            return ImmutableList.of(
                    new Outcome(IdxSponsorOutcome.TRUE.name(), bundle.getString("trueOutcome")),
                    new Outcome(IdxSponsorOutcome.FALSE.name(), bundle.getString("falseOutcome")),
                    new Outcome(IdxSponsorOutcome.CANCEL.name(), bundle.getString("cancelOutcome")),
                    new Outcome(IdxSponsorOutcome.EMAIL.name(), bundle.getString("emailOutcome")));
        }
    }


}