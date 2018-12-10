package com.lm.security.web;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

public class ShopifyHttpSessionOAuth2AuthorizationRequestRepository {
	private static final String DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME =
			HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST";

	private final String sessionAttributeName = DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME;
	
	
	@SuppressWarnings("unchecked")
	public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request) {
		String state = authorizationRequest.getState();
		
		HttpSession session = request.getSession(false);
		Map<String, OAuth2AuthorizationRequest> authorizationRequests = session == null ? null :
				(Map<String, OAuth2AuthorizationRequest>) session.getAttribute(this.sessionAttributeName);
		
		if (authorizationRequests == null) {
			authorizationRequests =  new HashMap<>();
		}		
		
		authorizationRequests.put(state, authorizationRequest);
		request.getSession().setAttribute(this.sessionAttributeName, authorizationRequests);

	}
	
	
	
}
