package com.lm.security.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;


public class ShopifyOAuth2AuthorizedClientService implements OAuth2AuthorizedClientService {
	
	private TokenService tokenService;
	
	public ShopifyOAuth2AuthorizedClientService(TokenService tokenService) {
		this.tokenService = tokenService;
	}
	
	/*
	 * Used by ShopifyExistingFilter to create an OAuth2AuthenticationToken
	 */

	@SuppressWarnings("unchecked")
	@Override
	public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId,
			String principalName) {
		
		OAuth2AuthorizedClient client = tokenService.getStore(principalName);
		
		if(client != null) {
			return (T) client;

		}
		return null;
	}

	/*
	 * Called by OAuth2LoginAuthenticationFilter upon successful authentication
	 * 
	 * Decides whether or not it should update the DB or add the new store
	 */
	@Override
	public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
		
		String shop = ((OAuth2AuthenticationToken)principal).getPrincipal().getName();
		boolean doesStoreExist = tokenService.doesStoreExist(shop);

		//OAuth2AuthorizedClient existingStore = loadAuthorizedClient(authorizedClient.getClientRegistration().getRegistrationId(), shop);

		if(doesStoreExist) {
			tokenService.updateStore(authorizedClient, principal);
		} else {
			tokenService.saveNewStore(authorizedClient, principal);

		}
	
	}

	@Override
	public void removeAuthorizedClient(String clientRegistrationId, String principalName) {

		
	}

}
