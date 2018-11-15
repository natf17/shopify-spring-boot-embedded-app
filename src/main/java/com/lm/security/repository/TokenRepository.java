package com.lm.security.repository;


public interface TokenRepository {
	EncryptedTokenAndSalt findTokenForRequest(String shop);

	
}
