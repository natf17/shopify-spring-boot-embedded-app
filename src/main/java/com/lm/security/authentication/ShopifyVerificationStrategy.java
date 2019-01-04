package com.lm.security.authentication;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.util.UriUtils;

import com.lm.security.web.ShopifyHttpSessionOAuth2AuthorizationRequestRepository;

public class ShopifyVerificationStrategy {
	public static final String NONCE_PARAMETER = OAuth2ParameterNames.STATE;
	public static final String HMAC_PARAMETER = "hmac";
	public static final String HMAC_HEADER = "X-Shopify-Hmac-SHA256";

	
	private ShopifyHttpSessionOAuth2AuthorizationRequestRepository authReqRepository;
	private ClientRegistrationRepository clientRegistrationRepository;
	
	
	public ShopifyVerificationStrategy(ClientRegistrationRepository clientRegistrationRepository, ShopifyHttpSessionOAuth2AuthorizationRequestRepository authReqRepository) {
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authReqRepository = authReqRepository;

	}
	
	/*
	 * Perform HMAC verification as directed by Shopify
	 */
	public boolean isShopifyRequest(HttpServletRequest request) {
		Map<String,String[]> requestParameters = this.getRequestParameters(request);
				
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
		
		String secret = getClientSecret(request);
		
		if(!isShopifyQueryRequest(request.getQueryString(), hmacValue, secret)) {
			// try again...
			// sometimes the query string has been url encoded (by the server...?)
			return isShopifyQueryRequest(UriUtils.decode(request.getQueryString(), StandardCharsets.UTF_8), hmacValue, secret);

		}
		
		return true;

		

		
	}
	
	private boolean isShopifyQueryRequest(String rawQueryString, String hmac, String secret) {

		String hmacQueryStringPiece = HMAC_PARAMETER + "=" + hmac + "&";

		String processedQuery = rawQueryString.replaceFirst(Pattern.quote(hmacQueryStringPiece), "");
				
		if(rawQueryString.equals(processedQuery)) {
			// maybe the hmac parameter is the last parameter
			
			processedQuery = rawQueryString.replaceFirst(Pattern.quote("&" + HMAC_PARAMETER + "=" + hmac), "");

			if(rawQueryString.equals(processedQuery)) {
				throw new RuntimeException("An error occurred processing the HMAC pair.");

			}
		}
		
		String shaOfQuery = hash(secret, processedQuery);
		
		if(shaOfQuery.equals(hmac)) {
			return true;
		}

		return false;
		
	}
	
	public boolean isShopifyHeaderRequest(String body, String hmac, String secret) {
		
		String hashValue = this.hash(secret, hmac);
		
		// From Shopify:
		// "Each webhook request includes a base64-encoded X-Shopify-Hmac-SHA256 header"
		
		String encodedValue = Base64.getEncoder().encodeToString(hashValue.getBytes());
		
		return encodedValue.equals(hmac);
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
		
		if(authorizationRequests != null) {
			if(authorizationRequests.keySet().contains(nonce)) {
				return true;
			}
			
			// try again...
			// Url-decode the nonce:
			nonce = UriUtils.decode(nonce, StandardCharsets.UTF_8);
			if(authorizationRequests.keySet().contains(nonce)) {
				return true;
			}
		}
	
		return false;
		
	}
	
	/*
	 * Note: This method is called 
	 * 
	 * 1. In an embedded app when HMAC verification must be done on the
	 * 	  install path 
	 * 
	 * 2. For every authorization redirect uri ("white-listed" urls)
	 * 
	 * In 1, the ClientRegistration is retrieved exclusively using the registration is extracted from the url 
	 * In 2, the ClientRegistration is retrieved exclusively using the session's OAuth2AuthorizationRequest's clientId.
	 */
	
	public String getClientSecret(HttpServletRequest req) {
		
		Map.Entry<String, OAuth2AuthorizationRequest> authReq = authReqRepository.getFirstAuthorizationRequest(req);
		String clientId = null;
		ClientRegistration reg = null;
		String clientSecret = null;
		
		// Prefer obtaining the ClientRegistration using the clientId saved in the OAuth2AuthorizationRequest
		// But in embedded app, this is the first time a request is made, so no
		// OAuth2AuthorizationRequest is in the session...
		if(authReq == null) {
			String registrationId = authReqRepository.extractRegistrationId(req);
			if(registrationId == null) {
				throw new RuntimeException("No registrationId found!");
			}
			
			clientSecret = getClientSecretByRegistrationId(registrationId);
			
		} else {
			clientId = authReq.getValue().getClientId();
			
			Iterator<ClientRegistration> it = ((InMemoryClientRegistrationRepository)clientRegistrationRepository).iterator();
			
			while(it.hasNext()) {
				ClientRegistration current = it.next();
				if(current.getClientId().equals(clientId)) {
					reg = current;
					break;
				}
			}
			
			if(reg == null) {
				throw new RuntimeException("No ClientRegistration found for " + clientId);
			}
			
			clientSecret = reg.getClientSecret();

		}
		
		if(clientSecret == null) {
			throw new RuntimeException("No client secret found");
		}
		
		return clientSecret;
		
	}
	
	public String getClientSecretByRegistrationId(String registrationId) {
		ClientRegistration reg = clientRegistrationRepository.findByRegistrationId(registrationId);
		
		if(reg == null) {
			return null;
		}
		
		return reg.getClientSecret();
	}
	
	public Map<String,String[]> getRequestParameters(HttpServletRequest req) {
		return req.getParameterMap();

	}
	public String hash(String secret, String message) {
		
		String hash = null;
		
		try {
			
			Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		    SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256");
		    sha256_HMAC.init(secret_key);

		    hash = Hex.encodeHexString(sha256_HMAC.doFinal(message.getBytes("UTF-8")));
		    
		}
		    catch (Exception e){
		     throw new RuntimeException("Error hashing");
		}
		
		return hash;
	}
	
	public String getBody(HttpServletRequest req) {
		InputStream in = null;
		 
		String body = null;
		try {
			in = req.getInputStream();
			IOUtils.toString(in, "UTF-8");
		} catch(IOException ex) {
			throw new RuntimeException("There was an error parsing the request body");
		}
		
		return body;
	}
	
	public boolean isHeaderShopifyRequest(HttpServletRequest request, String registrationId) {
		String hmacValue = request.getHeader(HMAC_HEADER);
		
		if(hmacValue == null || hmacValue.isEmpty()) {
			return false;
		}
		
		String secret = getClientSecretByRegistrationId(registrationId);
		
		String body = getBody(request);

		return isShopifyHeaderRequest(body, hmacValue, secret);
	}
	

}
