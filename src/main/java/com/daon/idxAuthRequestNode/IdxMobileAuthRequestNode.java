package com.daon.idxAuthRequestNode;

import static com.daon.idxAuthRequestNode.IdxCommon.getTenantRepoFactory;
import static com.daon.idxAuthRequestNode.IdxCommon.objectMapper;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import org.apache.commons.lang.StringUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.daon.identityx.rest.model.def.PolicyStatusEnum;
import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.daon.identityx.rest.model.pojo.User;
import com.google.inject.assistedinject.Assisted;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.collections.ApplicationCollection;
import com.identityx.clientSDK.collections.PolicyCollection;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.queryHolders.ApplicationQueryHolder;
import com.identityx.clientSDK.queryHolders.PolicyQueryHolder;
import com.identityx.clientSDK.repositories.ApplicationRepository;
import com.identityx.clientSDK.repositories.AuthenticationRequestRepository;
import com.identityx.clientSDK.repositories.PolicyRepository;
import com.sun.identity.sm.RequiredValueValidator;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.TextOutputCallback;

/**
 * A node that initiates an authentication request to IdentityX
 */
@Node.Metadata(outcomeProvider  = SingleOutcomeNode.OutcomeProvider.class,
        configClass      = IdxMobileAuthRequestNode.Config.class)
public class IdxMobileAuthRequestNode extends SingleOutcomeNode {

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * the IdentityX policy which should be used for authentication
         *
         * @return the policy name
         */
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        String policyName();

        /**
         * the IdentityX application to be used
         *
         * @return the application Id
         */
        @Attribute(order = 200, validators = {RequiredValueValidator.class})
        String applicationId();
    }

    private final Config config;
    private final Logger logger = LoggerFactory.getLogger("amAuth");

    /**
     * Create the node.
     */
    @Inject
    public IdxMobileAuthRequestNode(@Assisted Config config) {
        this.config = config;
    }


    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        Optional<TextOutputCallback> textOutputCallbackOptional = context.getCallback(TextOutputCallback.class);
        Optional<TextInputCallback> textInputCallbackOptional = context.getCallback(TextInputCallback.class);
        JsonValue sharedState = context.sharedState;
        String fidoAuthenticationRequest = context.sharedState.get("fidoAuthenticationRequest").asString();

        if (context.hasCallbacks() && textOutputCallbackOptional.isPresent() && textInputCallbackOptional.isPresent() &&
                StringUtils.equals(textOutputCallbackOptional.get().getMessage(), fidoAuthenticationRequest)) {

            sharedState.put("fidoAuthenticationResponse", textInputCallbackOptional.get().getText());
            return goToNext().replaceSharedState(sharedState).build();
        }
        User user;
        try {
            user = objectMapper.readValue(context.sharedState.get("Daon_User").asString(), User.class);
        } catch (IOException e) {
            throw new NodeProcessException(e);
        }

        TenantRepoFactory tenantRepoFactory = getTenantRepoFactory(context);
        logger.debug("Connected to the IdentityX Server");
        AuthenticationRequest request = new AuthenticationRequest();

        if (user == null) {
            String error = "Error retrieving user";
            logger.error(error);
            throw new NodeProcessException(error);
        } else {
            logger.debug("User found with ID " + user.getUserId());
            request.setUser(user);
            request.setServerData(context.sharedState.get(SharedStateConstants.USERNAME).asString());
        }

        String policyName = config.policyName();
        PolicyQueryHolder holder = new PolicyQueryHolder();
        holder.getSearchSpec().setPolicyId(policyName);
        holder.getSearchSpec().setStatus(PolicyStatusEnum.ACTIVE);
        PolicyRepository policyRepo = tenantRepoFactory.getPolicyRepo();
        PolicyCollection policyCollection;
        try {
            policyCollection = policyRepo.list(holder);
        } catch (IdxRestException e) {
            throw new NodeProcessException(e);
        }
        if(policyCollection.getItems().length > 0) {
            logger.debug("Setting Policy On Authentication Request");
            request.setPolicy(policyCollection.getItems()[0]);
        }
        else {
            logger.error("Could not find an active policy with the PolicyId: " + policyName);
            throw new NodeProcessException("Could not find an active policy with the PolicyId: " + policyName);
        }

        String appId = config.applicationId();
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


        request.setDescription("OpenAM has Requested an Authentication.");

        String txnRequestType = "FI";
        request.setType(txnRequestType);
        request.setOneTimePasswordEnabled(false);
        request.setAuthenticationRequestId(UUID.randomUUID().toString());

        AuthenticationRequestRepository authenticationRequestRepo = tenantRepoFactory.getAuthenticationRequestRepo();
        try {
            request = authenticationRequestRepo.create(request);
        } catch (IdxRestException e) {
            logger.debug("Error creating authentication request for user: " + user.getUserId());
            throw new NodeProcessException(e);
        }

        logger.debug("GetFidoAuthNRequest: " + request.getFidoAuthenticationRequest());
        AuthenticationRequest finalRequest = request;

        List<Callback> callbacks = new ArrayList<>();

        final JsonValue json = json(object(
                field("href", finalRequest.getHref()),
                field("id", finalRequest.getId()),
                field("fidoChallenge", finalRequest.getFidoChallenge()),
                field("fidoAuthenticationRequest", finalRequest.getFidoAuthenticationRequest())));


        callbacks.add(new TextInputCallback("Please provide the Daon Fido Response", "{}"));
        callbacks.add(new TextOutputCallback(TextOutputCallback.INFORMATION,
                                             json.toString()));


         return Action.send(callbacks).replaceSharedState(sharedState.put("fidoAuthenticationRequest",
                                                                          json.toString()).put(IdxCommon.IDX_HREF_KEY, finalRequest.getHref())).build();
    }

}