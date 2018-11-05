package com.lm.security.authentication;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public class AuthenticationRedirectUriHolder implements Authentication {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -7065164088368102238L;
	private String authenticationRedirectUri;
	
	public AuthenticationRedirectUriHolder(String authenticationRedirectUri) {
		this.authenticationRedirectUri = authenticationRedirectUri;
	}

	@Override
	public String getName() {
		return null;
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

	// only method of interest
	@Override
	public Object getPrincipal() {
		return this.authenticationRedirectUri;
	}

	@Override
	public boolean isAuthenticated() {
		return false;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

	}

}
