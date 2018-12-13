package com.lm.security.authentication;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import com.lm.security.web.ShopifyHttpSessionOAuth2AuthorizationRequestRepository;

public class ShopifyVerificationStrategy {
	public static final String NONCE_PARAMETER = "state";
	
	public boolean isShopifyRequest(HttpServletRequest request) {
		Map<String,String[]> requestParamters = request.getParameterMap();
		
		return false;
	}
	
	@SuppressWarnings("unchecked")
	public boolean hasValidNonce(HttpServletRequest request) {
		String nonce = request.getParameter(NONCE_PARAMETER);
		
		if(nonce == null || nonce.isEmpty()) {
			return false;
		}
		
		HttpSession session = request.getSession(false);
		Map<String, OAuth2AuthorizationRequest> authorizationRequests = session == null ? null :
				(Map<String, OAuth2AuthorizationRequest>) session.getAttribute(ShopifyHttpSessionOAuth2AuthorizationRequestRepository.DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME);
		if (authorizationRequests == null) {
			return false;
		}
		
		
		return true;
		
	}


}
