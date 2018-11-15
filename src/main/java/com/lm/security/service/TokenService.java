package com.lm.security.service;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
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
		System.out.println("TokenService looking for token");

		String shopName = request.getParameter(SHOP_ATTRIBUTE_NAME);
		EncryptedTokenAndSalt rawTokenAndSalt = null;
		
		if(shopName != null && !shopName.isEmpty()) {
			rawTokenAndSalt = this.tokenRepository.findTokenForRequest(shopName);
			
			if (rawTokenAndSalt != null) {
				System.out.println("Token found");
				return this.oAuth2LoginAuthenticationTokenFromAccessToken(request, rawTokenAndSalt);
			}
			
		}
		System.out.println("Shop not provided/found");
		
		return null;
	}
	
	
	
	/*
	 * 
	 */
	private OAuth2PersistedAuthenticationToken oAuth2LoginAuthenticationTokenFromAccessToken(HttpServletRequest request, EncryptedTokenAndSalt rawTokenAndSalt) {
		System.out.println("Extracting raw encrypted token");

		String encryptedToken = rawTokenAndSalt.getEncryptedToken();
		String salt = rawTokenAndSalt.getSalt();

			
		TextEncryptor textEncryptor = Encryptors.queryableText(cipherPassword.getPassword(), salt);

		
		System.out.println("Decrypting token");

		String decryptedToken = textEncryptor.decrypt(encryptedToken);
		System.out.println("decrypted: " + decryptedToken);
		
		System.out.println("Returning an OAuth2PersistedAuthenticationToken");

		
		OAuth2AccessToken newAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, decryptedToken, null, null);

		return new OAuth2PersistedAuthenticationToken(request.getParameter(SHOP_ATTRIBUTE_NAME), newAccessToken);

		
		
	}

}

