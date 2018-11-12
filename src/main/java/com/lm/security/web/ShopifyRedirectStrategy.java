package com.lm.security.web;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import com.lm.security.authentication.AuthenticationRedirectUriHolder;

public class ShopifyRedirectStrategy extends DefaultRedirectStrategy {
	public final String I_FRAME_REDIRECT_URI = "/oauth/authorize";

	public void saveRedirectAuthenticationUris(HttpServletRequest request, OAuth2AuthorizationRequest authorizationRequest) {
		
		String authorizationUri = authorizationRequest.getAuthorizationRequestUri();

		String parentFrameRedirectUrl = super.calculateRedirectUrl(request.getContextPath(), authorizationUri);
				
		
		SecurityContextHolder.getContext().setAuthentication(new AuthenticationRedirectUriHolder(
																addRedirectParams(parentFrameRedirectUrl, authorizationRequest), 
																addRedirectParams(I_FRAME_REDIRECT_URI, authorizationRequest)
																));
		
	}
	
	
	/*
	 * Adds the following query parameters to the string:
	 * 
	 * 1. client_id
	 * 2. redirect_uri
	 * 3. scope
	 * 4. state
	 */
	private String addRedirectParams(String uri, OAuth2AuthorizationRequest authorizationRequest) {
		
		LinkedMultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
		queryParams.add("client_id", authorizationRequest.getClientId());
		queryParams.add("redirect_uri", authorizationRequest.getRedirectUri());
		queryParams.addAll("scope", new ArrayList<>(authorizationRequest.getScopes()));
		queryParams.add("state", "nonce");
		
		
		
		return UriComponentsBuilder
								.fromPath(uri)
								.queryParams(queryParams)
								.build()
								.toString();


	}

}
