package com.lm.security.repository;

import java.util.Set;

public interface TokenRepository {
	EncryptedTokenAndSalt findTokenForRequest(String shop);
	void saveNewStore(String shop, Set<String>scopes, EncryptedTokenAndSalt encryptedTokenAndSalt);
	
}
