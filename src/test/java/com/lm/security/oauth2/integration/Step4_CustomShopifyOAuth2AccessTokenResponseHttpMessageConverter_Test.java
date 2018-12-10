package com.lm.security.oauth2.integration;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.web.client.HttpMessageConverterExtractor;

import com.lm.security.converter.CustomShopifyOAuth2AccessTokenResponseHttpMessageConverter;

public class Step4_CustomShopifyOAuth2AccessTokenResponseHttpMessageConverter_Test {
	

	/*
	 * Test the ShopifyAuthorizationCodeTokenResponseClient's
	 * CustomShopifyOAuth2AccessTokenResponseHttpMessageConverter.
	 * 
	 * The Step2 test verified that a valid OAuth2AuthorizationCodeGrantRequest
	 * was passed into the tokenReponseClient. Now, make sure the tokenReponseClient 
	 * prepares a valid POST request using the default FormHttpMessageConverter.
	 * 
	 * Given a response with body:
	 * 
	 * {	"access_token": "...",
	 * 		"scope": "write_orders,read_customers"
	 * }
	 * 
	 * Create a valid OAuth2AccessTokenResponse
	 * 
	 */
	
	@Test
	public void given_Shopify_Response_Then_ShopifyAuthorizationCodeTokenResponseClient_Creates_Valid_TokenResponse() throws Exception {

		String access_token = "f85632530bf277ec9ac6f649fc327f17";
		
		String scope = "write_orders,read_customers";
		
		Set<String> scopes = Stream.of("write_orders", "read_customers").collect(Collectors.toSet());
		
		String responseJson = "{\"access_token\": \"" + access_token + "\",\"scope\": \"" + scope + "\"}";
		
		// the mock barebones Shopify response
		ClientHttpResponse mockResponse = mock(ClientHttpResponse.class);
		
		HttpHeaders responseHeaders = new HttpHeaders();
		
		responseHeaders.add(HttpHeaders.CONTENT_TYPE, "application/json");
		
		InputStream is = new ByteArrayInputStream(responseJson.getBytes(StandardCharsets.UTF_8));
		
		when(mockResponse.getBody()).thenReturn(is);
		
		when(mockResponse.getHeaders()).thenReturn(responseHeaders);
		

		HttpMessageConverterExtractor<OAuth2AccessTokenResponse> extr = new HttpMessageConverterExtractor<>(
																			OAuth2AccessTokenResponse.class, Arrays.asList(
																						new FormHttpMessageConverter(),
																						new CustomShopifyOAuth2AccessTokenResponseHttpMessageConverter()));
		
		OAuth2AccessTokenResponse tokenResponse = extr.extractData(mockResponse);
		OAuth2AccessToken tokenObj = tokenResponse.getAccessToken();
		
		Assert.assertEquals(access_token, tokenObj.getTokenValue());
		Assert.assertTrue(tokenObj.getScopes().containsAll(scopes));
		

		
	}

}
