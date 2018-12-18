package com.daon.idxAuthRequestNode;

import static org.forgerock.openam.auth.node.api.Action.send;

import static com.daon.idxAuthRequestNode.IdxCommon.getTenantRepoFactory;

import com.daon.identityx.rest.model.def.PolicyStatusEnum;
import com.daon.identityx.rest.model.pojo.Sponsorship;
import com.daon.identityx.rest.model.pojo.Policy.PolicyTypeEnum;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.collections.ApplicationCollection;
import com.identityx.clientSDK.collections.PolicyCollection;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.queryHolders.ApplicationQueryHolder;
import com.identityx.clientSDK.queryHolders.PolicyQueryHolder;
import com.identityx.clientSDK.repositories.ApplicationRepository;
import com.identityx.clientSDK.repositories.PolicyRepository;
import com.identityx.clientSDK.repositories.SponsorshipRepository;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.sm.RequiredValueValidator;

import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;
import javax.inject.Inject;

import javax.security.auth.callback.TextOutputCallback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.authentication.callbacks.PollingWaitCallback;
import org.forgerock.openam.utils.qr.GenerationUtils;
import org.forgerock.openam.utils.qr.ErrorCorrectionLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
        configClass      = IdxSponsorUser.Config.class)
public class IdxSponsorUser extends AbstractDecisionNode {

    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * the IdenitityX policy which should be used for enrollment
         * @return the policy name
         */
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        String enrollmentPolicyName();

        /**
         * the IdenitityX application to be used
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

    }

    private final Config config;
    private final Logger logger = LoggerFactory.getLogger("amAuth");
    private final String IDX_QR_KEY = "idx-qr-key";
    private final String IDX_POLL_TIMES = "idx-poll-times-remaining";
    private final String IDX_SPONSORSHIP_HREF = "idx-sponsorship-href";

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
        Optional<ScriptTextOutputCallback> scriptTextOutputCallback = context.getCallback(ScriptTextOutputCallback
                 .class);
        String qrText;

        TenantRepoFactory tenantRepoFactory = getTenantRepoFactory(context);

        if (!sharedState.isDefined(IDX_QR_KEY) || !scriptTextOutputCallback.isPresent() || !scriptTextOutputCallback
                .get().getMessage().equals(sharedState.get(IDX_QR_KEY).asString())) {

            if (logger.isDebugEnabled()) {
                logger.debug("Entering into Sponsor User for the first time for user: " + sharedState.get
                        (SharedStateConstants.USERNAME).asString());
            }

            sharedState.put(IDX_POLL_TIMES, config.numberOfTimesToPoll());

            qrText = getQRText(tenantRepoFactory, sharedState.get(SharedStateConstants.USERNAME).asString());

            sharedState.put(IDX_SPONSORSHIP_HREF, sponsorshipHref);

            String qrCallback = GenerationUtils.getQRCodeGenerationJavascript("callback_0", qrText, 20,
                    ErrorCorrectionLevel.LOW);

            sharedState.put(IDX_QR_KEY, qrCallback);

            return buildResponse(sharedState);

        }
        if (isEnrolled(sharedState, tenantRepoFactory)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Enrollment Successful for: " + sharedState.get
                        (SharedStateConstants.USERNAME).asString());
            }
            // If enrollment is successful send user to next node
            return goTo(true).build();
        }

        // Build the callbacks and decrement from our configured number of poll times
        return buildResponse(sharedState);

    }

    private Action buildResponse(JsonValue sharedState) {
        Integer pollTimesRemaining = sharedState.get(IDX_POLL_TIMES).asInteger();
        if (pollTimesRemaining == 0) {
            // If number of times remaining to poll is 0, send user to false
            return goTo(false).replaceSharedState(sharedState).build();
        }
        sharedState.put(IDX_POLL_TIMES, pollTimesRemaining - 1);

        ScriptTextOutputCallback qrCodeCallback = new ScriptTextOutputCallback(sharedState.get(IDX_QR_KEY).asString());

        String step1 = "Step 1: Launch IdentityX app and scan QR code.";
        String step2 = "Step 2: Register your biometrics.";
        String step3 = "Step 3: Authenticate with biometrics when prompted in the app.";

        TextOutputCallback textOutputCallback1 = new TextOutputCallback(TextOutputCallback.INFORMATION, step1);
        TextOutputCallback textOutputCallback2 = new TextOutputCallback(TextOutputCallback.INFORMATION, step2);
        TextOutputCallback textOutputCallback3 = new TextOutputCallback(TextOutputCallback.INFORMATION, step3);

        return send(Arrays.asList(qrCodeCallback, new PollingWaitCallback(Integer
                .toString(config.pollingWaitInterval() * 1000), "waiting..."), textOutputCallback1, textOutputCallback2, textOutputCallback3))
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
        if (logger.isDebugEnabled()) {
            logger.debug("Checking Sponsorship Status for: " + sharedState.get
                    (SharedStateConstants.USERNAME).asString());
        }

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


}