package com.lm.security.filters;

import java.io.IOException;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.security.core.context.SecurityContextHolder;

import com.lm.security.authentication.ShopifyOriginToken;

/*
 * This filter checks the request to see if it came from Shopify.
 * 
 * If it did, it populates the SecurityContext with a ShopifyOriginToken.
 * 
 * If not, the ShopifyOriginToken is not set.
 * 
 */
public class ShopifyOriginFilter implements Filter {
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		System.out.println("ShopifyOriginFilter applied.");
		
		if(isShopifyRequest(request)) {
			System.out.println("Setting ShopifyOriginToken");
			SecurityContextHolder.getContext().setAuthentication(new ShopifyOriginToken(true));
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
	
}