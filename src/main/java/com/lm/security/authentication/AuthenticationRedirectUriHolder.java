package com.lm.security.authentication;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public class AuthenticationRedirectUriHolder implements Authentication {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -7065164088368102238L;
	private RedirectUris redirectUris;
	
	public AuthenticationRedirectUriHolder(String parentRedirectUri, String iFrameRedirectUri) {
		this.redirectUris = new RedirectUris(parentRedirectUri, iFrameRedirectUri);
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
		return this.redirectUris;
	}

	/*
	 * ExceptionTranslationFilter will never redirect to the AuthenticationEntryPoint, allowing the request to go through to the controller
	 * since the JS in the html page takes care of redirecting for authorization, and there's no "login page"
	 */
	@Override
	public boolean isAuthenticated() {
		return true;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

	}
	
	public static class RedirectUris {
		private final String parentRedirectUri;
		private final String iFrameRedirectUri;
		
		public RedirectUris(String parentRedirectUri, String iFrameRedirectUri) {
			this.parentRedirectUri = parentRedirectUri;
			this.iFrameRedirectUri = iFrameRedirectUri;
			
		}
		
		public String getParentRedirectUri() {
			return this.parentRedirectUri;
		}
		
		public String getIFrameRedirectUri() {
			return this.iFrameRedirectUri;
		}
		
	}

}
