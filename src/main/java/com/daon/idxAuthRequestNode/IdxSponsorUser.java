package com.daon.idxAuthRequestNode;

import static org.forgerock.openam.auth.node.api.Action.send;

import static com.daon.idxAuthRequestNode.IdxCommon.getTenantRepoFactory;

import com.daon.identityx.rest.model.def.PolicyStatusEnum;
import com.daon.identityx.rest.model.pojo.Sponsorship;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.collections.ApplicationCollection;
import com.identityx.clientSDK.collections.PolicyCollection;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.queryHolders.ApplicationQueryHolder;
import com.identityx.clientSDK.queryHolders.PolicyQueryHolder;
import com.identityx.clientSDK.repositories.ApplicationRepository;
import com.identityx.clientSDK.repositories.PolicyRepository;

import com.google.inject.assistedinject.Assisted;
import com.identityx.clientSDK.repositories.SponsorshipRepository;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.sm.RequiredValueValidator;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;
import java.net.URLEncoder;
import javax.inject.Inject;
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

        @Attribute(order = 300, validators = {RequiredValueValidator.class})
        int pollingWaitInterval();

        @Attribute(order = 400, validators = {RequiredValueValidator.class})
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
            qrText = getQRText(sharedState, tenantRepoFactory, sharedState.get
                    (SharedStateConstants.USERNAME).asString());
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

    private Action buildResponse(JsonValue sharedState, String qrCodeString) {
        Integer pollTimesRemaining = sharedState.get(IDX_POLL_TIMES).asInteger();
        if (pollTimesRemaining == 0) {
            // If number of times remaining to poll is 0, send user to false
            return goTo(false).replaceSharedState(sharedState).build();
        }
        sharedState.put(IDX_POLL_TIMES, pollTimesRemaining - 1);
        String qrCallback = GenerationUtils.getQRCodeGenerationJavascript("callback_0", qrCodeString, 20,
                ErrorCorrectionLevel.LOW);
        sharedState.put(IDX_QR_KEY, qrCallback);

        ScriptTextOutputCallback qrCodeCallback = new ScriptTextOutputCallback(qrCallback);

        return send(Arrays.asList(qrCodeCallback, new PollingWaitCallback(Integer
                .toString(config.pollingWaitInterval() * 1000), "Scan QR Code")))
                .replaceSharedState(sharedState).build();
    }

    private String getQRText(JsonValue sharedState, TenantRepoFactory tenantRepoFactory, String userId)
        throws NodeProcessException {
        //TODO Get the QRText from IdentityX

        //TODO - get these from config
        String appId = "FIDO";
        String policyId = "RegPolicy";
        //String appId = config.applicationId();
        //String policyId = config.enrollmentPolicyName();

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

        logger.debug("Sponsorship created for userId " + userId);
        logger.debug("Sponsorship Code: " + request.getSponsorshipToken());

        String qrCodeString = new String(request.getQrCode());
        logger.debug("QR code: " + qrCodeString);

        //return qrCodeString;

        //update - AM will build the QR code. Just need to provide the URL string
        String sponsorshipCodeUrl = "identityx://sponsor?SC=" + request.getSponsorshipToken();
        String encodedUrl;
        try {
            encodedUrl = URLEncoder.encode(sponsorshipCodeUrl, "UTF-8");
        }
        catch (UnsupportedEncodingException e) {
            logger.error("Error encoding QR Code Url");
            throw new NodeProcessException(e);
        }

        //try without encoding
        return sponsorshipCodeUrl;

    }

    private boolean isEnrolled(JsonValue sharedState) {
        if (logger.isDebugEnabled()) {
            logger.debug("Checking Enrollment Status for: " + sharedState.get
                    (SharedStateConstants.USERNAME).asString());
        }
        //TODO Get the enrollment status from Identity X
        return false;
    }


}