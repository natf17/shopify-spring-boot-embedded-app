package com.lm.security.service;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;

import com.lm.security.authentication.OAuth2PersistedAuthenticationToken;
import com.lm.security.repository.TokenRepository;

@Service
public class TokenService {
	
	public static final String SHOP_ATTRIBUTE_NAME = "shop";
	
	private TokenRepository tokenRepository;
	
	private BytesEncryptor encryptor;
	
	@Autowired
	public void setTokenRepository(TokenRepository tokenRepository) {
		this.tokenRepository = tokenRepository;
	}
	
	@Autowired
	public void setEncryptor(BytesEncryptor encryptor) {
		this.encryptor = encryptor;
	}
	
	public OAuth2PersistedAuthenticationToken findTokenForRequest(HttpServletRequest request) {
		System.out.println("TokenService looking for token");

		String shopName = request.getParameter(SHOP_ATTRIBUTE_NAME);
		OAuth2AccessToken rawToken = null;
		
		if(shopName != null && !shopName.isEmpty()) {
			rawToken = this.tokenRepository.findTokenForRequest(shopName);
			
			if (rawToken != null) {
				System.out.println("Token found");
				return this.oAuth2LoginAuthenticationTokenFromAccessToken(request, rawToken);
			}
			
		}
		System.out.println("Shop not provided/found");
		
		return null;
	}
	
	private OAuth2PersistedAuthenticationToken oAuth2LoginAuthenticationTokenFromAccessToken(HttpServletRequest request, OAuth2AccessToken rawToken) {
		System.out.println("Extracting raw encrypted token");

		String encryptedToken = rawToken.getTokenValue();
		
		System.out.println("Decrypting token");

		String decryptedToken = new String(encryptor.decrypt(encryptedToken.getBytes()));
		
		
		OAuth2AccessToken newAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, decryptedToken, null, null);
		
		System.out.println("Returning an OAuth2PersistedAuthenticationToken");

		return new OAuth2PersistedAuthenticationToken(request.getParameter(SHOP_ATTRIBUTE_NAME), newAccessToken);
		
		
	}

}

