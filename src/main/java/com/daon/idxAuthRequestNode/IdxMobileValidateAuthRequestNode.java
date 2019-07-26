package com.daon.idxAuthRequestNode;

import static com.daon.idxAuthRequestNode.IdxCommon.getTenantRepoFactory;

import javax.inject.Inject;

import org.apache.http.util.TextUtils;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;

import org.forgerock.openam.auth.node.api.TreeContext;
import org.json.JSONException;
import org.json.JSONObject;
import com.daon.identityx.rest.model.def.AuthenticationRequestStatusEnum;
import com.daon.identityx.rest.model.pojo.AuthenticationRequest;
import com.google.inject.assistedinject.Assisted;
import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.exceptions.IdxRestException;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * A node that validates an authentication request to IdentityX
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = IdxMobileValidateAuthRequestNode.Config.class)
public class IdxMobileValidateAuthRequestNode extends AbstractDecisionNode {

	private static LoggerWrapper logger = new LoggerWrapper();
	
	public interface Config {
		
		@Attribute(order = 100, validators = { RequiredValueValidator.class })
		default AuthenticationRequestStatusEnum expectedStatus() {
			return AuthenticationRequestStatusEnum.COMPLETED_SUCCESSFUL;
		}	
	}
	
	private final Config nodeConfig;	
	
	 /**
     * Create the node.
     */
    @Inject
    public IdxMobileValidateAuthRequestNode(@Assisted Config config) {
        this.nodeConfig = config;
    }

	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		
		String test = null;
		JSONObject obj = null;
		boolean isJsonOk = false;

		try {
			obj = new JSONObject(context.sharedState.get(IdxCommon.IDX_AUTH_RESPONSE_UAF).asString());
			logger.debug("Json={}", obj.toString());
		} catch (JSONException e) {
			logger.warn("Cannot cast SharedState Key = [{}] to JSON Object = {}", IdxCommon.IDX_AUTH_RESPONSE_UAF, e.getMessage());
		}

		if (obj != null) {
			
			try {
				test = obj.getString(IdxCommon.IDX_AUTH_RESPONSE_UAF);
				isJsonOk = true;
			} catch (JSONException e) {
				logger.warn("Cannot cast JSON Object Property = [{}] to JSON Object = {}", IdxCommon.IDX_AUTH_RESPONSE_UAF, e.getMessage());
			}
		}

		logger.debug("Test={}", test);

		if (TextUtils.isEmpty(test) || !isJsonOk) {
			test = context.sharedState.get(IdxCommon.IDX_AUTH_RESPONSE_UAF).asString();
			logger.debug("Using-Postman={}", test);
		}

		if (validateAuthResponse(test, context)) {
			return goTo(true)
					.replaceSharedState(context.sharedState)				
					.build();
		}
		return goTo(false).build();
	}

	private boolean validateAuthResponse(String authResponse, TreeContext context) throws NodeProcessException {

		// Call API to check status. Return true, false or pending get the authHref value from sharedState
		String authHref = context.sharedState.get(IdxCommon.IDX_HREF_KEY).asString();
				
		try {
			
			TenantRepoFactory tenantRepoFactory = getTenantRepoFactory(context);			
			
			AuthenticationRequest request = tenantRepoFactory.getAuthenticationRequestRepo().get(authHref);
			
			if (request == null) {
				logger.error("AuthRequest Href = {} is invalid", authHref);
				return false;
			}
			
			request.setFidoAuthenticationResponse(authResponse);
			
			request = tenantRepoFactory.getAuthenticationRequestRepo().update(request);
			
			logger.debug("Checking Status=[{}]", nodeConfig.expectedStatus());
			
			if (request.getStatus() == nodeConfig.expectedStatus()) {
				logger.debug("Success Status=[{}]", nodeConfig.expectedStatus());
				context.sharedState.put(IdxCommon.IDX_HREF_KEY, request.getHref());
				//Required for 'Daon ADoS SRP Passcode Authenticator' [D409#9302|D409#8302]
				context.sharedState.put(IdxCommon.IDX_AUTH_RESPONSE_UAF, request.getFidoAuthenticationResponse());
				return true;
			}
			
			logger.error("AuthRequest Status = {} is invalid", request.getStatus());
			return false;
			
		} catch (IdxRestException ex) {
			logger.error("validateAuthResponse exception", ex);
			return false;
		}
	}
}
