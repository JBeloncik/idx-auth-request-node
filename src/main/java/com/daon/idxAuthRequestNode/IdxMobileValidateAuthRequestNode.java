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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

	private final Logger logger = LoggerFactory.getLogger("amAuth");
	
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
			obj = new JSONObject(context.sharedState.get(IdxCommon.AUTH_RESPONSE_NAME).asString());
			logger.debug("Json={}", test);
		} catch (JSONException e) {
			logger.warn("JSONException1", e);
		}

		if (obj != null) {
			
			try {
				test = obj.getString(IdxCommon.AUTH_RESPONSE_NAME);
				isJsonOk = true;
			} catch (JSONException e) {
				logger.warn("JSONException2", e);
			}
		}

		logger.debug("Test={}", test);

		if (TextUtils.isEmpty(test) || !isJsonOk) {
			test = context.sharedState.get(IdxCommon.AUTH_RESPONSE_NAME).asString();
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
