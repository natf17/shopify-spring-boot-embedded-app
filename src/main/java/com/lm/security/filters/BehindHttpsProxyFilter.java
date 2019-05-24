package com.lm.security.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/* 
 * 
 * A problem occurs if this application is running behind a reverse proxy, because Shopify requires 
 * SSL connections, and although the reverse proxy might connect to Shopify via SSL, the HttpServletRequest
 * object will still have "http" as its scheme. This is problematic, because although the 
 * ShopifyOAuth2AuthorizationRequestResolver is hard coded to create a redirect uri with an https scheme,
 * which is stored in OAuth2AuthorizationRequest, the default OAuth2LoginAuthenticationProvider uses the 
 * OAuth2AuthorizationExchangeValidator to compare the current url (http) to the redirect uri (https). 
 * 
 * This filter wraps the redirectionPath (/login/app/oauth2/code/...) and loginPath (/install/...) in a 
 * HttpServletRequestWrapper that overrides the scheme to https and server port to 443
 * 
 * NOTE: This filter should only be activated if Spring Boot is receiving http requests and the reverse proxy
 * is using https (as Shopify requires).
 * 
 */
public class BehindHttpsProxyFilter implements Filter {

	private AntPathRequestMatcher redirectionPath;
	private AntPathRequestMatcher loginPath;
	
	
	public BehindHttpsProxyFilter(String redirectionPath, String loginPath) {
		this.redirectionPath = new AntPathRequestMatcher(redirectionPath);
		this.loginPath = new AntPathRequestMatcher(loginPath);

	}
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest req = (HttpServletRequest)request;

		if(!redirectionPath.matches(req) && !loginPath.matches(req)) {

			chain.doFilter(request, response);
			
			return;
		}
		
		chain.doFilter(new HttpsRequest(req), response);
		
	}
	
	static class HttpsRequest extends HttpServletRequestWrapper {
		
		public HttpsRequest(HttpServletRequest request) {
			super(request);
		}
		
		@Override
		public String getScheme() {
			return "https";
		}
		
		@Override
		public int getServerPort() {

			return 443;
		}
	}

}