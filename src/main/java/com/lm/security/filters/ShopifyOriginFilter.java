package com.lm.security.filters;

import static org.mockito.Mockito.RETURNS_DEEP_STUBS;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.lm.security.authentication.OAuth2PersistedAuthenticationToken;
import com.lm.security.authentication.ShopifyOriginToken;

/*
 * This filter checks the request to see if it came from Shopify.
 * It only checks the paths passed in via the constructor (matchedPaths and the restrictedPath)
 * 
 * If there's a match on the path, and it isn't already "Shopify" authenticated, it populates 
 * the SecurityContext with a ShopifyOriginToken.
 * 
 * If not, the ShopifyOriginToken is not set.
 * 
 * However, for the url path provided, if the request did not come from Shopify, instead of
 * setting the ShopifyOriginToken, it will throw an error.
 * 
 * 
 */
public class ShopifyOriginFilter implements Filter {

	private AntPathRequestMatcher mustComeFromShopifyMatcher;
	private List<AntPathRequestMatcher> applicablePaths;

	
	public ShopifyOriginFilter(String restrictedPath, String... matchedPaths) {
		this.mustComeFromShopifyMatcher = new AntPathRequestMatcher(restrictedPath);
		
		applicablePaths = new ArrayList<>();
		applicablePaths.add(mustComeFromShopifyMatcher);
		Arrays.stream(matchedPaths).forEach(i -> applicablePaths.add(new AntPathRequestMatcher(i)));
		
	}
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		if(!applyFilter(request)) {
			
			chain.doFilter(request, response);
			
			return;
		}
		
		if(isShopifyRequest(request)) {

			if(!isAlreadyAuthenticated()) {
				SecurityContextHolder.getContext().setAuthentication(new ShopifyOriginToken(true));
			}
		} else {
			if(mustComeFromShopifyMatcher.matches((HttpServletRequest)request)) {
				throw new RuntimeException("REQUEST MUST COME SHOPIFY");
				
			}
		}
		
		chain.doFilter(request, response);

	}
	
	/*
	 * 1. Removes hmac parameter from query string
	 * 2. Builds query string
	 * 3. HMAC-SHA256(query)
	 * 4. Is (3) = hmac value?
	 */
	private boolean isShopifyRequest(ServletRequest request) {
		Map<String,String[]> requestParamters = request.getParameterMap();
		
		
		
		
		return true;
	}
	
	private boolean isAlreadyAuthenticated() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		
		if(auth instanceof OAuth2PersistedAuthenticationToken || auth instanceof OAuth2AuthenticationToken) {
			return true;
		}
		
		return false;

	}
	
	private boolean applyFilter(ServletRequest request) {
		HttpServletRequest req = (HttpServletRequest)request;
		
		boolean match = this.applicablePaths.stream().anyMatch(i -> i.matches(req));
		
		return match;
		
	}
	
}