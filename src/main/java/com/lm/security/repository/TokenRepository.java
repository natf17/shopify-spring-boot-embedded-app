package com.lm.security.repository;

import org.springframework.security.oauth2.core.OAuth2AccessToken;

public interface TokenRepository {
	OAuth2AccessToken findTokenForRequest(String shop);

}
