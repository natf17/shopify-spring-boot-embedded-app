package com.lm.security.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.lm.security.authentication.AuthenticationRedirectUriHolder;

// stores the Access Token as an attribute

public class ShopifyStore extends AuthenticationRedirectUriHolder.RedirectUris implements OAuth2User {
	public static final String ACCESS_TOKEN_KEY = "shopify_access_token";

	private final String name;
	private final Collection<? extends GrantedAuthority> authorities;
	private final Map<String, Object> attributes;
	
	public ShopifyStore(String name, String accessToken) {			
		this(name, null, null);
		this.attributes.put(ACCESS_TOKEN_KEY, accessToken);

		
	}
	
	public ShopifyStore(String name, Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes) {
		super(null, null);
		this.name = name;
		this.authorities =  authorities != null ? authorities : new ArrayList<>();
		this.attributes =  attributes != null ? attributes : new HashMap<>();
	}

	@Override
	public String getName() {
		return this.name;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return this.attributes;
	}
	

}
