package com.lm.security.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.lm.security.authentication.ShopifyVerificationStrategy;
import com.lm.security.service.TokenService;

public class UninstallFilter implements Filter {
	
	private AntPathRequestMatcher matcher;
	private ShopifyVerificationStrategy verificationStrategy;
	private TokenService tokenService;
	private final String SHOP_HEADER = "X-Shopify-Shop-Domain";
	
	
	public UninstallFilter(String uninstallEndpoint, ShopifyVerificationStrategy verificationStrategy, TokenService tokenService) {
		this.matcher = new AntPathRequestMatcher(uninstallEndpoint + "/{registrationId}");
		this.verificationStrategy = verificationStrategy;
		this.tokenService = tokenService;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest)request;
		HttpServletResponse resp = (HttpServletResponse)response;
		
		String registrationId = matches(req);
		
		
		
		if(registrationId == null) {
			chain.doFilter(req, response);
			return;
		}
		
		if(this.verificationStrategy.isHeaderShopifyRequest(req, registrationId)) {
			doUninstall(req, resp);
			unininstallSuccess(req, resp);
			
			return;
		}
		
		uninstallFailure(req, resp);
		
		return;
		
		
	}
	
	protected String matches(HttpServletRequest request) {
		if(this.matcher.matches(request)) {
			return this.matcher.extractUriTemplateVariables(request).get("registrationId");
		}
		return null;
		
	}
	
	public void doUninstall(HttpServletRequest request, HttpServletResponse response) {
		String storeName = request.getHeader(SHOP_HEADER);
		
		if(storeName == null || storeName.isEmpty()) {
			uninstallFailure(request, response);
		}
		
		this.tokenService.uninstallStore(storeName);
	}
	
	protected void unininstallSuccess(HttpServletRequest req, HttpServletResponse resp) {
		resp.setStatus(200);
	}
	
	protected void uninstallFailure(HttpServletRequest req, HttpServletResponse resp) {
		throw new RuntimeException("Uninstall failure");
	}

}
