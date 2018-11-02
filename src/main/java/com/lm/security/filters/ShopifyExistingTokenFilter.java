package com.lm.security.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class ShopifyExistingTokenFilter implements Filter {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// attempts to find a token for this store, and if it's found, set the Authentication in SecurityContextHolder
		// if not, simply continue
		
	}
	
}
