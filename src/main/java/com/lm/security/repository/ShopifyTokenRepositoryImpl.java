package com.lm.security.repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Set;

import static java.util.stream.Collectors.joining;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;


@Repository
public class ShopifyTokenRepositoryImpl implements TokenRepository {
	
	private static String SELECT_TOKEN_FOR_SHOP = "SELECT access_token, salt FROM StoreAccessTokens WHERE shop=?";
	private static final String SAVE_ACCESS_TOKEN_CREDENTIALS = "INSERT INTO StoreAccessTokens(shop,access_token,salt,scope) VALUES(?,?,?,?)";
	
	private JdbcTemplate jdbc;
	
	@Autowired
	public void setJdbc(JdbcTemplate jdbc) {
		this.jdbc = jdbc;
	}

	@Override
	public EncryptedTokenAndSalt findTokenForRequest(String shop) {
		EncryptedTokenAndSalt token = null;
		
		try {
			token = jdbc.queryForObject(SELECT_TOKEN_FOR_SHOP, new StoreTokensMapper(), shop);
		} catch(EmptyResultDataAccessException ex) {
			token = null;

		}

		return token;
	}
	
	class StoreTokensMapper implements RowMapper<EncryptedTokenAndSalt> {

		@Override
		public EncryptedTokenAndSalt mapRow(ResultSet rs, int arg) throws SQLException {
			String encryptedToken = rs.getString("access_token");
			String salt = rs.getString("salt");
			
			return new EncryptedTokenAndSalt(encryptedToken, salt);
		
		}
		
	}



	@Override
	public void saveNewStore(String shop, Set<String> scopes, EncryptedTokenAndSalt encryptedTokenAndSalt) {
		String scopeString = scopes.stream()
										.collect(joining(","));
		
		jdbc.update(SAVE_ACCESS_TOKEN_CREDENTIALS, shop, encryptedTokenAndSalt.getEncryptedToken(), encryptedTokenAndSalt.getSalt(), scopeString);

	}
	
}
