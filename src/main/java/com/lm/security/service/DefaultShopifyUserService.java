package com.lm.security.service;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.lm.security.web.ShopifyOAuth2AuthorizationRequestResolver;

/*
 * Since the default OAuth2LoginAuthenticationProvider sets the OAuth2User as the principal,
 * and since our application will need the authentication token for every request, it will
 * be stored as an additional parameter in the OAuth2User.
 * 
 * The OAuth2UserRequest has the shop parameter because our custom ShopifyAuthorizationCodeTokenResponseClient
 * stored it there.
 * 
 */

public class DefaultShopifyUserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
	public static final String ACCESS_TOKEN_KEY = "shopify_access_token";
	

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		Object shopName = userRequest.getAdditionalParameters().get(ShopifyOAuth2AuthorizationRequestResolver.SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN);
		
		return new ShopifyStore((String)shopName, userRequest.getAccessToken().getTokenValue());
	}
	
	
	// stores the Access Token as an attribute
	class ShopifyStore implements OAuth2User {
		
		private final String name;
		private final Collection<? extends GrantedAuthority> authorities;
		private final Map<String, Object> attributes;
		
		public ShopifyStore(String name, String accessToken) {			
			this(name, null, null);
			
			this.attributes.put(ACCESS_TOKEN_KEY, accessToken);

			
		}
		
		public ShopifyStore(String name, Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes) {
			this.name = name;
			this.authorities = authorities;
			this.attributes = attributes;
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

}
