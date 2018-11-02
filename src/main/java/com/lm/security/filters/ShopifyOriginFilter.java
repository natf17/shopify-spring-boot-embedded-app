package com.lm.security.filters;

import java.io.IOException;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class ShopifyOriginFilter implements Filter {
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		System.out.println("ShopifyOriginFilter applied.");
		
		if(isShopifyRequest(request)) {
			chain.doFilter(request, response);
		}
		
		
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