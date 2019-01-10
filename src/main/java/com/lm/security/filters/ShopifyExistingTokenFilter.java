package com.lm.security.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import com.lm.security.authentication.ShopifyOriginToken;
import com.lm.security.configuration.SecurityBeansConfig;
import com.lm.security.service.TokenService;
import com.lm.security.service.ShopifyStore;

/* 
 * This filter checks the SecurityContextHolder for a ShopifyOriginToken to determine whether this request came from Shopify.
 * 
 * If it did, this filter attempts to find a token for the store.
 * If there is no token, the SecurityContextHolder's Authentication is left untouched.
 * 
 * If the request did not come from Shopify, the SecurityContextHolder's Authentication is left untouched.

 */

public class ShopifyExistingTokenFilter extends GenericFilterBean {
	
	private TokenService tokenService;
	private AntPathRequestMatcher requestMatcher;
	
	public ShopifyExistingTokenFilter(TokenService tokenService, String loginEndpoint) {
		this.tokenService = tokenService;
		this.requestMatcher = new AntPathRequestMatcher(loginEndpoint);
		
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest req = (HttpServletRequest) request;
		
		if(!requestMatcher.matches(req)) {
			chain.doFilter(request, response);

			return;

		}
		

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		ShopifyOriginToken originToken = null;
		OAuth2AuthenticationToken oauth2Token = null;
		
		if(auth != null && auth instanceof ShopifyOriginToken) {
System.out.println("ShopifyOriginToken found");
			originToken = (ShopifyOriginToken)auth;
			
			if(originToken.isFromShopify()) {

				oauth2Token = this.getToken(req);
				if(oauth2Token != null) {
					System.out.println("Setting token");

					this.setToken(oauth2Token);
				}
				
			}
			
			// if ShopifyOriginToken is still in the SecurityContextHolder, remove it
			if(SecurityContextHolder.getContext().getAuthentication() instanceof ShopifyOriginToken) {
				SecurityContextHolder.getContext().setAuthentication(null);
			}
			
			
		}
		
		System.out.println("ShopifyExistingTokenFilter");

		chain.doFilter(request, response);
		
		
	}
	
	private void setToken(OAuth2AuthenticationToken oauth2Token) {

		SecurityContextHolder.getContext().setAuthentication(oauth2Token);
	}
	
	private OAuth2AuthenticationToken getToken(HttpServletRequest request) {
		
		String shopName = request.getParameter(TokenService.SHOP_ATTRIBUTE_NAME);
		
		if(shopName == null || shopName.isEmpty()) {
			return null;
		}
		
		
		OAuth2AuthorizedClient client = tokenService.getStore(shopName);
		
		if(client == null) {
			// this store "has not been installed", or salt and passwords are outdated
			return null;
		}

		// create a OAuth2AuthenticationToken
		
		OAuth2AuthenticationToken oauth2Authentication = new OAuth2AuthenticationToken(
				transformAuthorizedClientToUser(client),
				null,
				SecurityBeansConfig.SHOPIFY_REGISTRATION_ID);
		
		return oauth2Authentication;
	}
	
	
	private OAuth2User transformAuthorizedClientToUser(OAuth2AuthorizedClient client) {
		return new ShopifyStore(client.getPrincipalName(),
														  client.getAccessToken().getTokenValue());
	}
	
	
	
}
