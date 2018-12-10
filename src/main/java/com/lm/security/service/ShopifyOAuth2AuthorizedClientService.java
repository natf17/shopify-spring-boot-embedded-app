package com.lm.security.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;


public class ShopifyOAuth2AuthorizedClientService implements OAuth2AuthorizedClientService {
	
	private TokenService tokenService;
	
	public ShopifyOAuth2AuthorizedClientService(TokenService tokenService) {
		this.tokenService = tokenService;
	}
	

	@Override
	public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId,
			String principalName) {

		return null;
	}

	@Override
	public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
		tokenService.saveNewStore(authorizedClient, principal);
	
	}

	@Override
	public void removeAuthorizedClient(String clientRegistrationId, String principalName) {

		
	}

}
