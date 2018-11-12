package com.lm.security.repository;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Repository;


@Repository
public class ShopifyTokenRepositoryImpl implements TokenRepository {
	
	private static String SELECT_TOKEN_FOR_SHOP = "SELECT (access_token, scopes) FROM StoreOAuthTokens WHERE shop = ?";
	
	private JdbcTemplate jdbc;
	
	@Autowired
	public void setJdbc(JdbcTemplate jdbc) {
		this.jdbc = jdbc;
	}

	@Override
	public OAuth2AccessToken findTokenForRequest(String shop) {
		
		OAuth2AccessToken token = null;
		
		try {
			token = jdbc.queryForObject(SELECT_TOKEN_FOR_SHOP, new StoreTokensMapper(), shop);
		} catch(EmptyResultDataAccessException ex) {
			token = null;
		}

		return token;
	}
	
	class StoreTokensMapper implements RowMapper<OAuth2AccessToken> {

		@Override
		public OAuth2AccessToken mapRow(ResultSet rs, int arg) throws SQLException {
			String encryptedToken = rs.getString("access_token");
			
			OAuth2AccessToken newAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, encryptedToken, null, null);

			
			return newAccessToken;
		}
		
	}

}
