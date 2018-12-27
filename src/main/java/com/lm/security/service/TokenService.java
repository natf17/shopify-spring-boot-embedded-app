package com.lm.security.service;

import java.util.Set;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;

import com.lm.security.authentication.CipherPassword;
import com.lm.security.configuration.SecurityBeansConfig;
import com.lm.security.repository.EncryptedTokenAndSalt;
import com.lm.security.repository.TokenRepository;
import com.lm.security.repository.TokenRepository.OAuth2AccessTokenWithSalt;

@Service
public class TokenService {
	
	public static final String SHOP_ATTRIBUTE_NAME = "shop";
	
	private TokenRepository tokenRepository;
	private CipherPassword cipherPassword;
	private ClientRegistrationRepository clientRepository;
	
	
	@Autowired
	public void setTokenRepository(TokenRepository tokenRepository) {
		this.tokenRepository = tokenRepository;
	}
	
	@Autowired
	public void setCipherPassword(CipherPassword cipherPassword) {
		this.cipherPassword = cipherPassword;
	}
	
	@Autowired
	public void setClientRepository(ClientRegistrationRepository clientRepository) {
		this.clientRepository = clientRepository;
	}
	
	public void saveNewStore(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
		
		String shop = getStoreName(principal);
		
		Set<String> scopes = authorizedClient.getAccessToken().getScopes();
		
		EncryptedTokenAndSalt encryptedTokenAndSalt = getTokenAndSalt(authorizedClient);
		
		
		this.tokenRepository.saveNewStore(shop, scopes, encryptedTokenAndSalt);
		
		
	}

	public OAuth2AuthorizedClient getStore(String shopName) {
		
		OAuth2AccessTokenWithSalt ets = this.tokenRepository.findTokenForRequest(shopName);
		
		if(ets == null) {
			return null;
		}
		
		OAuth2AccessToken rawToken = getRawToken(ets);
		
		ClientRegistration cr = clientRepository.findByRegistrationId(SecurityBeansConfig.SHOPIFY_REGISTRATION_ID);
		
		if(cr == null) {
			throw new RuntimeException("An error occurred retrieving the ClientRegistration for " + SecurityBeansConfig.SHOPIFY_REGISTRATION_ID);
		}
		
		return new OAuth2AuthorizedClient(
				cr,
				shopName,
				rawToken,
				null);
		
	}
	

	
	public void updateStore(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
		
		String shop = getStoreName(principal);

		EncryptedTokenAndSalt encryptedTokenAndSalt = getTokenAndSalt(authorizedClient);
		
		this.tokenRepository.updateKey(shop, encryptedTokenAndSalt);

	}
	
	
	
	private String getStoreName(Authentication principal) {
		String shop = ((OAuth2AuthenticationToken)principal).getPrincipal().getName();

		return shop;
	}
	
	private OAuth2AccessToken getRawToken(OAuth2AccessTokenWithSalt toS) {
		String salt = toS.getSalt();
		
		OAuth2AccessToken enTok = toS.getAccess_token();
		String decryptedToken = decryptToken(new EncryptedTokenAndSalt(enTok.getTokenValue(), salt));
		
		return new OAuth2AccessToken(enTok.getTokenType(),
									 decryptedToken,
									 enTok.getIssuedAt(),
									 enTok.getExpiresAt(),
									 enTok.getScopes());
	}
	
	private EncryptedTokenAndSalt getTokenAndSalt(OAuth2AuthorizedClient authorizedClient) {
		
		String rawAccessTokenValue = authorizedClient.getAccessToken().getTokenValue();
		
		String genSalt = KeyGenerators.string().generateKey();
		
		TextEncryptor encryptor = Encryptors.queryableText(cipherPassword.getPassword(), genSalt);
		
		return new EncryptedTokenAndSalt(encryptor.encrypt(rawAccessTokenValue), genSalt);
		
	}
	
	
	private String decryptToken(EncryptedTokenAndSalt enC) {
		TextEncryptor textEncryptor = Encryptors.queryableText(cipherPassword.getPassword(), enC.getSalt());

		String decryptedToken = textEncryptor.decrypt(enC.getEncryptedToken());
		
		return decryptedToken;
		
		
	}

}

