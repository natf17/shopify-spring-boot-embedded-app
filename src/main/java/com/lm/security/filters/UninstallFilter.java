package com.lm.security.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.lm.security.authentication.ShopifyVerificationStrategy;
import com.lm.security.service.TokenService;

public class UninstallFilter implements Filter {
	
	private AntPathRequestMatcher matcher;
	private ShopifyVerificationStrategy verificationStrategy;
	private TokenService tokenService;
	private HttpMessageConverter<Object> messageConverter;
	
	
	public UninstallFilter(String uninstallEndpoint, ShopifyVerificationStrategy verificationStrategy, TokenService tokenService, HttpMessageConverter<Object> converter) {
		this.matcher = new AntPathRequestMatcher(uninstallEndpoint + "/{registrationId}");
		this.verificationStrategy = verificationStrategy;
		this.tokenService = tokenService;
		this.messageConverter = converter;
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
	
	public void doUninstall(HttpServletRequest request, HttpServletResponse response) throws IOException{
		UninstallMessage body = this.extractBody(request);

		if(body == null) {
			uninstallFailure(request, response);
		}
		String storeName = body.getShop_domain();
		
		if(storeName == null || storeName.isEmpty()) {
			uninstallFailure(request, response);
		}

		this.tokenService.uninstallStore(storeName);
	}
	
	protected void unininstallSuccess(HttpServletRequest req, HttpServletResponse resp) {

		resp.setStatus(200);
	}
	
	protected void uninstallFailure(HttpServletRequest req, HttpServletResponse resp) throws IOException{

		resp.sendError(403, "This request must come from Shopify");
	}
	
	private UninstallMessage extractBody(HttpServletRequest request) {
		ServletServerHttpRequest message = new ServletServerHttpRequest(request);
		UninstallMessage msg;
		try {
			msg = (UninstallMessage)this.messageConverter.read(UninstallMessage.class, message);
		} catch (Exception ex){
			return null;
		}
		
		return msg;
	}
	
	static class UninstallMessage {
		private String shop_id;
		private String shop_domain;
		
		public void setShop_id(String shop_id) {
			this.shop_id = shop_id;
		}
		
		public String getShop_id() {
			return this.shop_id;
		}
		
		public void setShop_domain(String shop_domain) {
			this.shop_domain = shop_domain;
		}
		
		public String getShop_domain() {
			return this.shop_domain;
		}
		
		
	}

}
