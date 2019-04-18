package com.daon.idxAuthRequestNode;

import static com.daon.idxAuthRequestNode.IdxCommon.IDX_HREF_KEY;
import static com.daon.idxAuthRequestNode.IdxCommon.getTenantRepoFactory;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.daon.identityx.rest.model.def.AuthenticationRequestStatusEnum;
import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.identityx.clientSDK.repositories.AuthenticationRequestRepository;
import com.identityx.clientSDK.repositories.UserRepository;

/**
 * A node that validates an authentication request to IdentityX
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class, configClass =
         IdxMobileValidateAuthRequestNode.Config.class)
public class IdxMobileValidateAuthRequestNode extends AbstractDecisionNode {

    private final Logger logger = LoggerFactory.getLogger("amAuth");

    public interface Config {

    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
         String response = context.sharedState.get("fidoAuthenticationResponse").asString();
         JsonValue fidoAuthenticationResponse = JsonValue.json(response);
         String json = fidoAuthenticationResponse.get("fidoAuthenticationResponse").asString();

         String test = null;
         JSONObject obj = null;
        try {
            obj = new JSONObject(context.sharedState.get("fidoAuthenticationResponse").asString());
        } catch (JSONException e) {
            e.printStackTrace();
        }
        try {
            test = obj.getString("fidoAuthenticationResponse");
        } catch (JSONException e) {
            e.printStackTrace();
        }


        if (validateAuthResponse(test, context)) {
            return goTo(true).build();
        }
        return goTo(false).build();
    }

    private boolean validateAuthResponse(String authResponse, TreeContext context) throws NodeProcessException {

        //call API to check status. Return true, false or pending
        //get the authHref value from sharedState
        String authHref = context.sharedState.get(IDX_HREF_KEY).asString();
        try {
            TenantRepoFactory tenantRepoFactory = getTenantRepoFactory(context);

            AuthenticationRequestRepository authenticationRequestRepo = tenantRepoFactory.getAuthenticationRequestRepo();
            AuthenticationRequest request = authenticationRequestRepo.get(authHref);
            if (request == null) {
                String error = "Unable to find the authentication request with HREF: " + authHref;
                logger.error(error);
                throw new RuntimeException(error); }
            request.setFidoAuthenticationResponse(authResponse);
            request = authenticationRequestRepo.update(request);
            if (request.getStatus() == AuthenticationRequestStatusEnum.COMPLETED_SUCCESSFUL) {
                return true;
            }
            String error = "Response could not be validated";
            logger.error(error);
            throw new NodeProcessException(error);
        } catch (IdxRestException ex) {
            String error = "An exception occurred while attempting to update the registration challenge." +
                    " Exception: " + ex.getMessage(); logger.error(error, ex);
            throw new NodeProcessException(error, ex); }
    }
}

