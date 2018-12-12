package com.lm.security.service;

import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;

import com.lm.security.authentication.CipherPassword;
import com.lm.security.authentication.OAuth2PersistedAuthenticationToken;
import com.lm.security.repository.EncryptedTokenAndSalt;
import com.lm.security.repository.TokenRepository;

@Service
public class TokenService {
	
	public static final String SHOP_ATTRIBUTE_NAME = "shop";
	
	private TokenRepository tokenRepository;
	private CipherPassword cipherPassword;
	
	
	@Autowired
	public void setTokenRepository(TokenRepository tokenRepository) {
		this.tokenRepository = tokenRepository;
	}
	
	@Autowired
	public void setCipherPassword(CipherPassword cipherPassword) {
		this.cipherPassword = cipherPassword;
	}
	
	
	public OAuth2PersistedAuthenticationToken findTokenForRequest(HttpServletRequest request) {

		String shopName = request.getParameter(SHOP_ATTRIBUTE_NAME);
		EncryptedTokenAndSalt rawTokenAndSalt = null;
		
		if(shopName != null && !shopName.isEmpty()) {
			rawTokenAndSalt = this.tokenRepository.findTokenForRequest(shopName);
			
			if (rawTokenAndSalt != null) {
				return this.oAuth2LoginAuthenticationTokenFromAccessToken(request, rawTokenAndSalt);
			}
			
		}
		
		return null;
	}
	
	public void saveNewStore(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
		String shop = ((OAuth2AuthenticationToken)principal).getPrincipal().getName();
		
		Set<String> scopes = authorizedClient.getAccessToken().getScopes();
		
		String rawAccessTokenValue = authorizedClient.getAccessToken().getTokenValue();
		
		String genSalt = KeyGenerators.string().generateKey();
		
		TextEncryptor encryptor = Encryptors.queryableText(cipherPassword.getPassword(), genSalt);
		
		EncryptedTokenAndSalt encryptedTokenAndSalt = new EncryptedTokenAndSalt(encryptor.decrypt(rawAccessTokenValue), genSalt);
		
		
		this.tokenRepository.saveNewStore(shop, scopes, encryptedTokenAndSalt);
		
	}
	
	
	
	/*
	 * 
	 */
	private OAuth2PersistedAuthenticationToken oAuth2LoginAuthenticationTokenFromAccessToken(HttpServletRequest request, EncryptedTokenAndSalt rawTokenAndSalt) {

		String encryptedToken = rawTokenAndSalt.getEncryptedToken();
		String salt = rawTokenAndSalt.getSalt();

			
		TextEncryptor textEncryptor = Encryptors.queryableText(cipherPassword.getPassword(), salt);

		

		String decryptedToken = textEncryptor.decrypt(encryptedToken);
		
		OAuth2AccessToken newAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, decryptedToken, null, null);

		return new OAuth2PersistedAuthenticationToken(request.getParameter(SHOP_ATTRIBUTE_NAME), newAccessToken);

		
		
	}

}

