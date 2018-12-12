package com.lm.security.authentication;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

public class ShopifyVerificationStrategy {
	
	public boolean isShopifyRequest(HttpServletRequest request) {
		Map<String,String[]> requestParamters = request.getParameterMap();
		
		return false;
	}
	
	public boolean hasValidNonce(HttpServletRequest request) {
		return false;
	}


}
