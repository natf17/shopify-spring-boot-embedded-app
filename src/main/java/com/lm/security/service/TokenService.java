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
	
	private static final String SHOP_ATTRIBUTE_NAME = "shop";
	
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
		String shopName = request.getParameter(SHOP_ATTRIBUTE_NAME);
		OAuth2AccessToken rawToken = null;
		
		if(shopName != null && !shopName.isEmpty()) {
			rawToken = this.tokenRepository.findTokenForRequest(shopName);
			
			if (rawToken != null) {
				return oAuth2LoginAuthenticationTokenFromAccessToken(request, rawToken);
			}
			
		}
		
		return null;
	}
	
	private OAuth2PersistedAuthenticationToken oAuth2LoginAuthenticationTokenFromAccessToken(HttpServletRequest request, OAuth2AccessToken rawToken) {
		String encryptedToken = rawToken.getTokenValue();
		
		String decryptedToken = new String(encryptor.decrypt(encryptedToken.getBytes()));
		
		
		OAuth2AccessToken newAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, decryptedToken, null, null);
		
		return new OAuth2PersistedAuthenticationToken(request.getParameter(SHOP_ATTRIBUTE_NAME), newAccessToken);
		
		
	}

}

