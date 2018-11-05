package com.lm.security.web;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;

import com.lm.security.authentication.AuthenticationRedirectUriHolder;

public class ShopifyRedirectStrategy extends DefaultRedirectStrategy {

	public void saveRedirectAuthenticationUri(HttpServletRequest request, String url) {
		
		String redirectUrl = super.calculateRedirectUrl(request.getContextPath(), url);
		
		SecurityContextHolder.getContext().setAuthentication(new AuthenticationRedirectUriHolder(redirectUrl));
		
	}

}
