package com.lm.security.web;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/*
 * This class is called by OAuth2RequestRedirectFilter
 * and will always return null to prevent redirection (as this is taken care of by the Shopify javascript)
 * 
 */
public class ShopifyOauth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest arg0, String arg1) {
		// TODO Auto-generated method stub
		return null;
	}
	

}
