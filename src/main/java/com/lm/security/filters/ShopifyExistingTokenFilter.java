package com.lm.security.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.filter.GenericFilterBean;

import com.lm.security.authentication.OAuth2PersistedAuthenticationToken;
import com.lm.security.authentication.ShopifyOriginToken;
import com.lm.security.service.TokenService;

/* 
 * This filter checks the SecurityContextHolder for a ShopifyOriginToken to determine whether this request came from Shopify.
 * 
 * If it did, this filter attempts to find a token for the store.
 * If there is no token, the SecurityContextHolder's Authentication is left untouched.
 * 
 * If the request did not come from Shopify, the request came from Shopify, the SecurityContextHolder's Authentication is left untouched.

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
		
		System.out.println("Applying ShopifyExistingTokenFilter");

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		ShopifyOriginToken originToken = null;
		OAuth2PersistedAuthenticationToken oauth2Token = null;
		
		if(auth != null && auth instanceof ShopifyOriginToken) {
			System.out.println("ShopifyExistingTokenFilter found ShopifyOriginToken in the Authentication");

			originToken = (ShopifyOriginToken)auth;
			
			if(originToken.isFromShopify()) {
				System.out.println("... and it IS from Shopify");

				oauth2Token = this.getToken(req);
				if(oauth2Token != null) {
					this.setToken(oauth2Token);
				}
				
			}
		}
		
		chain.doFilter(request, response);
		
	}
	
	private void setToken(OAuth2PersistedAuthenticationToken oauth2Token) {
		SecurityContextHolder.getContext().setAuthentication(oauth2Token);
	}
	
	private OAuth2PersistedAuthenticationToken getToken(HttpServletRequest request) {
		System.out.println("Looking for token");

		
		return tokenService.findTokenForRequest(request);
	}
	
	
	
}
