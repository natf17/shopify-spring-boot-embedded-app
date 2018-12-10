package com.lm.security.web;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;


import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.lm.security.converter.CustomShopifyOAuth2AccessTokenResponseHttpMessageConverter;

/*
 * This implementation of OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
 * modifies the OAuth2AuthorizationCodeGrantRequest's clientRegistration
 * by using the shop name to generate a valid tokenUri.
 * 
 * It also makes sure the shop name is available later (by the OAuth2UserService) by saving the shop name
 * as an additional parameter in the OAuth2AccessTokenResponse
 * 
 * 
 */
public class ShopifyAuthorizationCodeTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
	
	private DefaultAuthorizationCodeTokenResponseClient oAuth2AccessTokenResponseClient;
	
	
	
	public ShopifyAuthorizationCodeTokenResponseClient() {
		RestTemplate restTemplate = new RestTemplate(Arrays.asList(
			new FormHttpMessageConverter(), new CustomShopifyOAuth2AccessTokenResponseHttpMessageConverter()));
	
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
		
		
		oAuth2AccessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
		oAuth2AccessTokenResponseClient.setRestOperations(restTemplate);
		
	}
	
	
	
	
	
	@Override
	public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
		
		ClientRegistration currentRegistration = authorizationGrantRequest.getClientRegistration();
		OAuth2AuthorizationExchange currentExchange = authorizationGrantRequest.getAuthorizationExchange();
		
		
		String tokenUriTemplate = currentRegistration.getProviderDetails().getTokenUri();
		
		Map<String,Object> additionalParams = currentExchange.getAuthorizationRequest().getAdditionalParameters();
		
		String shopName = (additionalParams.containsKey(ShopifyOAuth2AuthorizationRequestResolver.SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN)) ? (String)additionalParams.get(ShopifyOAuth2AuthorizationRequestResolver.SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN) : null;
		
		if(shopName == null) {
			throw new RuntimeException("Shop name not found in the OAuth2AuthorizationRequest");
		}
		
		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put(ShopifyOAuth2AuthorizationRequestResolver.SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN, shopName);
		String tokenUri = UriComponentsBuilder
				.fromHttpUrl(tokenUriTemplate)
				.buildAndExpand(uriVariables)
				.toUriString();
		
		ClientRegistration newClientRegistration = ClientRegistration.withRegistrationId(currentRegistration.getRegistrationId())
	            .clientId(currentRegistration.getClientId())
	            .clientSecret(currentRegistration.getClientSecret())
	            .clientAuthenticationMethod(currentRegistration.getClientAuthenticationMethod())
	            .authorizationGrantType(currentRegistration.getAuthorizationGrantType())
	            .redirectUriTemplate(currentRegistration.getRedirectUriTemplate())
	            .scope(currentRegistration.getScopes())
	            .authorizationUri(currentRegistration.getProviderDetails().getAuthorizationUri())
	            .tokenUri(tokenUri)
	            .clientName(currentRegistration.getClientName())
	            .build();
		
		OAuth2AuthorizationCodeGrantRequest newGrantReq = new OAuth2AuthorizationCodeGrantRequest(newClientRegistration, currentExchange);
		
		OAuth2AccessTokenResponse resp = oAuth2AccessTokenResponseClient.getTokenResponse(newGrantReq);
				
		
		resp.getAdditionalParameters().replace(ShopifyOAuth2AuthorizationRequestResolver.SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN, shopName);
		
		return resp;
	}
	
	// for testing purposes
	public void setRestOperations(RestOperations restOperations) {
		oAuth2AccessTokenResponseClient.setRestOperations(restOperations);
	}
	
	
	
}
