package com.lm.security.authentication;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import com.lm.security.web.ShopifyHttpSessionOAuth2AuthorizationRequestRepository;

public class ShopifyVerificationStrategy {
	public static final String NONCE_PARAMETER = OAuth2ParameterNames.STATE;
	public static final String HMAC_PARAMETER = "hmac";
	
	private ShopifyHttpSessionOAuth2AuthorizationRequestRepository authReqRepository;
	
	
	public ShopifyVerificationStrategy(ShopifyHttpSessionOAuth2AuthorizationRequestRepository authReqRepository) {
		this.authReqRepository = authReqRepository;
	}
	
	public boolean isShopifyRequest(HttpServletRequest request) {
		Map<String,String[]> requestParameters = request.getParameterMap();
				
		if(requestParameters == null) {
			return false;
			
		}
		
		String[] hmacValues = requestParameters.get(HMAC_PARAMETER);
		
		if(hmacValues == null || hmacValues.length != 1) {

			return false;
		}
		
		String hmacValue = hmacValues[0];
		
		if(hmacValue.isEmpty()) {

			return false;
		}
		
		// use the "valid" hmac value...
		
		String originalQuery = request.getQueryString();
		
		String hmacQueryStringPiece = HMAC_PARAMETER + "=" + hmacValue + "&";
		
		String processedQuery = originalQuery.replaceFirst(hmacQueryStringPiece, "");
				
		if(originalQuery.equals(processedQuery)) {
			// maybe the hmac parameter is the last parameter
			processedQuery = originalQuery.replaceFirst("&" + HMAC_PARAMETER + "=" + hmacValue, "");
			
			if(originalQuery.equals(processedQuery)) {
				throw new RuntimeException("An error occurred processing the HMAC pair.");

			}
		}
		
		String shaOfQuery = DigestUtils.sha256Hex(processedQuery);
		
		if(shaOfQuery.equals(hmacValue)) {
			return true;
		}

		return false;
	}
	
	/*
	 * This method makes sure there is an OAuth2AuthorizationRequest in the HttpSession
	 * that matches the nonce that was provided in this request.
	 * 
	 * This ensures that the nonce sent by the server (Shopify) matches the one 
	 * previously sent by the client (us)
	 * 
	 */
	
	public boolean hasValidNonce(HttpServletRequest request) {
		String nonce = request.getParameter(NONCE_PARAMETER);
		
		if(nonce == null || nonce.isEmpty()) {
			return false;
		}
		
		Map<String,OAuth2AuthorizationRequest> authorizationRequests = authReqRepository.getAuthorizationRequests(request);
		
		if(authorizationRequests != null && authorizationRequests.keySet().contains(nonce)) {
			return true;
		}
	
		return false;
		
	}
	

}
