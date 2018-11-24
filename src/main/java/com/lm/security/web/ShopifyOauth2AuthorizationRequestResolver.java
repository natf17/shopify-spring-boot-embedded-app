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
	public static final String SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN = "shop"; // must match template variable in ClientRegistration token_uri
	
	private ClientRegistrationRepository clientRegistrationRepository;
	private AntPathRequestMatcher authorizationRequestMatcher;
	private final StringKeyGenerator stateGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());
	private final ShopifyRedirectStrategy authorizationRedirectStrategy = new ShopifyRedirectStrategy();
	private final ShopifyHttpSessionOAuth2AuthorizationRequestRepository customAuthorizationRequestRepository = new ShopifyHttpSessionOAuth2AuthorizationRequestRepository();

	
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
		System.out.println("OAuth2AuthorizationRequestRedirectFilter: ShopifyOauth2AuthorizationRequestResolver");
		
		System.out.println("Is there a match with " + this.authorizationRequestMatcher.getPattern());
		if (this.authorizationRequestMatcher.matches(request)) {
			System.out.println("Match for ShopifyOauth2AuthorizationRequestResolver");
			registrationId = this.authorizationRequestMatcher
					.extractUriTemplateVariables(request).get("registrationId");
		} else {
			registrationId = null;
		}
		
		if(registrationId == null) {
			return null;
		}
		
		System.out.println("Registration id " + registrationId);

		System.out.println("Searching for a ClientRegistration for " + registrationId);
		// obtain a ClientRegistration for extracted registrationId
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
		if (clientRegistration == null) {
			throw new IllegalArgumentException("Invalid Client Registration: " + registrationId);
		}
		
		System.out.println("Found a ClientRegistration for " + registrationId);

		
		// only the Authorization code grant is accepted
		OAuth2AuthorizationRequest.Builder builder;
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
			builder = OAuth2AuthorizationRequest.authorizationCode();
		} else {
			throw new IllegalArgumentException("Invalid Authorization Grant Type ("  +
					clientRegistration.getAuthorizationGrantType().getValue() +
					") for Client Registration: " + clientRegistration.getRegistrationId());
		}
		
		
		
		System.out.println("Expanding the redirectUri...");
		String redirectUriStr = this.expandRedirectUri(request, clientRegistration);

		System.out.println("... " + redirectUriStr);

		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId());
		additionalParameters.put(SHOPIFY_SHOP_PARAMETER_KEY_FOR_TOKEN, this.getShopName(request));
		

		System.out.println("Building the OAuth2AuthorizationRequest");
		OAuth2AuthorizationRequest authorizationRequest = builder
				.clientId(clientRegistration.getClientId())
				.authorizationUri(this.generateAuthorizationUri(request, clientRegistration.getProviderDetails().getAuthorizationUri()))
				.redirectUri(redirectUriStr)
				.scopes(clientRegistration.getScopes())
				.state(this.stateGenerator.generateKey())
				.additionalParameters(additionalParameters)
				.build();


		System.out.println("Delegating to ClientRegistrationRepository");
		// Save the OAuth2AuthorizationRequest
		customAuthorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request);
		
				
		// DO NOT redirect, build redirecturi: DefaultRedirectStrategy		
		authorizationRedirectStrategy.saveRedirectAuthenticationUris(request, authorizationRequest);
		
		System.out.println("ShopifyOauth2AuthorizationRequestResolver resolve(req) returning");
		
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
		System.out.println("Received: " + authorizationUriTemplate);
		String shopName = this.getShopName(request);
		
		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put("shop", shopName);
		
		String authorizationUri = UriComponentsBuilder
							.fromHttpUrl(authorizationUriTemplate)
							.buildAndExpand(uriVariables)
							.toUriString();
		
		System.out.println("Returning: " + authorizationUri);

		return authorizationUri;
	}
	
	private String getShopName(HttpServletRequest request) {
		String shopName = request.getParameter(TokenService.SHOP_ATTRIBUTE_NAME);
		
		if(shopName == null || shopName.isEmpty()) {
			throw new RuntimeException("Shop name not found in request paramters");
		}
		
		return shopName;
	}

}
