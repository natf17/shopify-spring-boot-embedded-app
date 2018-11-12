package com.lm.security.authentication;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

public class OAuth2PersistedAuthenticationToken implements Authentication {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 6093851611534223158L;
	private boolean isAuthenticated;
	private OAuth2AccessToken token;
	private String storeName;
	
	public OAuth2PersistedAuthenticationToken(String storeName, OAuth2AccessToken token) {
		this.isAuthenticated = true;
		this.token = token;
		this.storeName = storeName;
	}
	
	public OAuth2AccessToken getToken() {
		return this.token;
	}
	
	public String storeName() {
		return this.storeName;
	}

	@Override
	public String getName() {
		return "persistedToken";
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return null;
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getDetails() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return null;
	}

	@Override
	public boolean isAuthenticated() {
		return this.isAuthenticated;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		this.isAuthenticated = isAuthenticated;
	}
	
	

}
