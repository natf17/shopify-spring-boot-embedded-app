package com.lm.security.web;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

public class ShopifyHttpSessionOAuth2AuthorizationRequestRepository {
	public static final String DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME =
			HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST";
	
	
	@SuppressWarnings("unchecked")
	public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request) {
		String state = authorizationRequest.getState();
		
		HttpSession session = request.getSession(false);
		Map<String, OAuth2AuthorizationRequest> authorizationRequests = session == null ? null :
				(Map<String, OAuth2AuthorizationRequest>) session.getAttribute(DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME);
		
		if (authorizationRequests == null) {
			authorizationRequests =  new HashMap<>();
		}		
		
		authorizationRequests.put(state, authorizationRequest);
		request.getSession().setAttribute(DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME, authorizationRequests);

	}
	
	
	@SuppressWarnings("unchecked")
	public Map<String, OAuth2AuthorizationRequest> getAuthorizationRequests(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		Map<String, OAuth2AuthorizationRequest> authorizationRequests = session == null ? null :
				(Map<String, OAuth2AuthorizationRequest>) session.getAttribute(DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME);
		if (authorizationRequests == null) {
			return new HashMap<>();
		}
		return authorizationRequests;
	}
	
	
}
