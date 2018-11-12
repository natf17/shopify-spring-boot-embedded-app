package com.lm.security.web;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.util.UriComponentsBuilder;

import com.lm.security.service.TokenService;

/*
 * This class is called by OAuth2RequestRedirectFilter
 * and resolve(req) always return null to prevent redirection (as this is taken care of by the Shopify javascript)
 * 
 */
public class ShopifyOauth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
	private static final String SHOPIFY_REGISTRATION_ID = "shopify";
	
	private ClientRegistrationRepository clientRegistrationRepository;
	private AntPathRequestMatcher authorizationRequestMatcher;
	private final StringKeyGenerator stateGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());
	private final ShopifyRedirectStrategy authorizationRedirectStrategy = new ShopifyRedirectStrategy();
	ShopifyHttpSessionOAuth2AuthorizationRequestRepository customAuthorizationRequestRepository = new ShopifyHttpSessionOAuth2AuthorizationRequestRepository();

	
	public ShopifyOauth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository,
			String authorizationRequestBaseUri) {

		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizationRequestMatcher = new AntPathRequestMatcher(
				authorizationRequestBaseUri + "/{registrationId}");
	}
	

	/*
	 * In DefaultOAuth2AuthorizationRequestResolver, this method is expected to redirect the user to 
	 */
	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
		
		// extract the registrationId (ex: "shopify")
		String registrationId;
		if (this.authorizationRequestMatcher.matches(request)) {
			registrationId = this.authorizationRequestMatcher
					.extractUriTemplateVariables(request).get("registrationId");
		} else {
			registrationId = null;
		}
		
		if(registrationId == null) {
			return null;
		}
		
		// obtain a ClientRegistration for extracted registrationId
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
		if (clientRegistration == null) {
			throw new IllegalArgumentException("Invalid Client Registration: " + registrationId);
		}
		
		// only the Authorization code grant is accepted
		OAuth2AuthorizationRequest.Builder builder;
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
			builder = OAuth2AuthorizationRequest.authorizationCode();
		} else {
			throw new IllegalArgumentException("Invalid Authorization Grant Type ("  +
					clientRegistration.getAuthorizationGrantType().getValue() +
					") for Client Registration: " + clientRegistration.getRegistrationId());
		}
		
		
		
		
		String redirectUriStr = this.expandRedirectUri(request, clientRegistration);

		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId());
		
		

		OAuth2AuthorizationRequest authorizationRequest = builder
				.clientId(clientRegistration.getClientId())
				.authorizationUri(this.generateAuthorizationUri(request, clientRegistration.getProviderDetails().getAuthorizationUri()))
				.redirectUri(redirectUriStr)
				.scopes(clientRegistration.getScopes())
				.state(this.stateGenerator.generateKey())
				.additionalParameters(additionalParameters)
				.build();


		// Save the OAuth2AuthorizationRequest
		customAuthorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request);
		
				
		// DO NOT redirect, build redirecturi: DefaultRedirectStrategy		
		authorizationRedirectStrategy.saveRedirectAuthenticationUris(request, authorizationRequest);
		
		
		return null;
	}

	
	
	/* Method called by the OAuth2RequestRedirectFilter to handle a ClientAuthorizationRequiredException
	* and create a redirect uri to the authorization server.
	* This scenario should never occur, so return null.
	*/
	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest req, String registrationId) {

		return null;
	}
	
	private String expandRedirectUri(HttpServletRequest request, ClientRegistration clientRegistration) {
		// Supported URI variables -> baseUrl, registrationId
		// EX: "{baseUrl}/oauth2/code/{registrationId}"
		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put("registrationId", clientRegistration.getRegistrationId());
		String baseUrl = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replaceQuery(null)
				.replacePath(request.getContextPath())
				.build()
				.toUriString();
		uriVariables.put("baseUrl", baseUrl);

		return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUriTemplate())
				.buildAndExpand(uriVariables)
				.toUriString();
	}
	
	
	/*
	 * Expects a shop request parameter to generate the authorization uri
	 */
	private String generateAuthorizationUri(HttpServletRequest request, String authorizationUriTemplate) {
		String shopName = request.getParameter(TokenService.SHOP_ATTRIBUTE_NAME);
		
		if(shopName == null || shopName.isEmpty()) {
			throw new RuntimeException("Shop name not found in request paramters");
		}
		
		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put("shop", shopName);
		
		String authorizationUri = UriComponentsBuilder
							.fromHttpUrl(authorizationUriTemplate)
							.buildAndExpand(uriVariables)
							.toUriString();
		
		
		return authorizationUri;
	}

}
