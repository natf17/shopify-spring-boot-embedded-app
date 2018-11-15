package com.lm.security.repository;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Repository;


@Repository
public class ShopifyTokenRepositoryImpl implements TokenRepository {
	
	private static String SELECT_TOKEN_FOR_SHOP = "SELECT access_token, salt FROM StoreAccessTokens WHERE shop=?";
	
	private JdbcTemplate jdbc;
	
	@Autowired
	public void setJdbc(JdbcTemplate jdbc) {
		this.jdbc = jdbc;
	}

	@Override
	public EncryptedTokenAndSalt findTokenForRequest(String shop) {
		System.out.println("ShopifyTokenRepositoryImpl looking for token for " + shop);
		EncryptedTokenAndSalt token = null;
		
		try {
			token = jdbc.queryForObject(SELECT_TOKEN_FOR_SHOP, new StoreTokensMapper(), shop);
		} catch(EmptyResultDataAccessException ex) {
			token = null;
			System.out.println("No token found");

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
	


}
