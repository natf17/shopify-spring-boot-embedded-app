package com.lm.security.repository;

import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;

public interface TokenRepository {
	EncryptedTokenAndSalt findTokenForRequest(String shop);
	void saveNewStore(String shop, Set<String>scopes, EncryptedTokenAndSalt encryptedTokenAndSalt);
	
}
