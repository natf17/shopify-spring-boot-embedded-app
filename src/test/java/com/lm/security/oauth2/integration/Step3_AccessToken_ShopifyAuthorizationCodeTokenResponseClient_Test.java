package com.lm.security.oauth2.integration;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;


import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;


import javax.servlet.http.HttpSession;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.lm.ShopifyEmbeddedAppSpringBootApplication;
import com.lm.security.authentication.CipherPassword;
import com.lm.security.oauth2.integration.config.DisabledShopifyVerfificationConfig;
import com.lm.security.oauth2.integration.config.TestConfig;
import com.lm.security.web.ShopifyAuthorizationCodeTokenResponseClient;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes= {ShopifyEmbeddedAppSpringBootApplication.class, TestConfig.class, DisabledShopifyVerfificationConfig.class})
@AutoConfigureMockMvc
public class Step3_AccessToken_ShopifyAuthorizationCodeTokenResponseClient_Test {
	
	@Autowired
	private MockMvc mockMvc;
	
	@Autowired
	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
	
	@Autowired
	private JdbcTemplate jdbc; 
	
	@Autowired
	private CipherPassword cipherPassword;
	
	private String SESSION_ATTRIBUTE_NAME = HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST";
	
	private OAuth2AuthorizationCodeGrantRequest caughtAuthorizationCodeGrantRequest;
	
	private String CODE = "sample_code_returned_by_Shopify";
	
	private String HMAC = "da9d83c171400a41f8db91a950508985";
	
	private String TIMESTAMP = "1409617544";
	
	private String SHOP = "newstoretest.myshopify.com";

	private String SHOPIFY_TOKEN_URI = "https://" + SHOP + "/admin/oauth/access_token";
	
	
	/*
	 * Perform the initial Authorization request and grab objects stored in the HttpSession
	 * that will be used to "continue" the session in the test
	 * 
	 * Capture the OAuth2AuthorizationCodeGrantRequest passed into OAuth2AccessTokenResponseClient.getTokenResponse(...)
	 * so that our custom client can be tested
	 * 
	 */
	@SuppressWarnings("unchecked")
	@Before
	public void initializeValue() throws Exception {

		String sampleSalt = KeyGenerators.string().generateKey();
		TextEncryptor encryptor = Encryptors.queryableText(cipherPassword.getPassword(), sampleSalt);

		jdbc.update("UPDATE STOREACCESSTOKENS SET access_token=?, salt=? WHERE shop='lmdev.myshopify.com'", encryptor.encrypt("sample"), sampleSalt);
		
		
		// part 1 - shop will install app, save OAuth2AuthorizationRequest in the session
		MvcResult mR = this.mockMvc.perform(get("/install/shopify?shop=newstoretest.myshopify.com&timestamp=dsd&hmac=sdfasrf4324")).andReturn();

		HttpSession rSession = mR.getRequest().getSession();
		
		Map<String, OAuth2AuthorizationRequest> oAuth2AuthorizationRequests = (Map<String, OAuth2AuthorizationRequest>)rSession.getAttribute(SESSION_ATTRIBUTE_NAME);
		
		
		// part 2 - Shopify redirects to the client, client prepares POST request
		Iterator<Entry<String, OAuth2AuthorizationRequest>> it = oAuth2AuthorizationRequests.entrySet().iterator();
		
		String state = it.next().getKey();
		
		MockHttpSession session = new MockHttpSession();
		session.setAttribute(SESSION_ATTRIBUTE_NAME, oAuth2AuthorizationRequests);
		

		
		// configure mock accessTokenResponseClient (used by OAuth2LoginAuthenticationProvider's authenticate(auth))
		// the request itself should fail
		when(accessTokenResponseClient.getTokenResponse(ArgumentMatchers.any())).thenThrow(new OAuth2AuthorizationException(new OAuth2Error("502")));
		
		this.mockMvc.perform(get("/login/app/oauth2/code/shopify?code=" + CODE + "&hmac=" + HMAC + "&timestamp=" + TIMESTAMP + "&state=" + state + "&shop=" + SHOP).session(session)).andReturn();

		ArgumentCaptor<OAuth2AuthorizationCodeGrantRequest> grantRequest = ArgumentCaptor.forClass(OAuth2AuthorizationCodeGrantRequest.class);
		

		verify(accessTokenResponseClient).getTokenResponse(grantRequest.capture());
		
		
		// capture the OAuth2AuthorizationCodeGrantRequest
		caughtAuthorizationCodeGrantRequest = grantRequest.getValue();	
		
	}
	
	
	
	/*
	 * Test the ShopifyAuthorizationCodeTokenResponseClient.
	 * 
	 * The Step2 test verified that a valid OAuth2AuthorizationCodeGrantRequest
	 * was passed into the tokenReponseClient. Now, make sure the tokenReponseClient 
	 * prepares a valid POST request using the default FormHttpMessageConverter.
	 * 
	 * Make sure:
	 * 
	 * 1. uri: the processed token uri
	 * 2. POST method
	 * 3. The body contains the following parameters: 
	 * 
	 * 		client_id: The API key for the app, as defined in the Partner Dashboard.
	 * 		client_secret: The API secret key for the app, as defined in the Partner Dashboard.
	 * 		code: The same code sent back by SHOPIFY
	 */
	
	@SuppressWarnings("unchecked")
	@Test
	public void given_OAuth2AuthorizationCodeGrantRequest_Then_FormHttpMessageConverter_Creates_Valid_TokenRequest() throws Exception {

		ShopifyAuthorizationCodeTokenResponseClient oAuth2AccessTokenResponseClient = new ShopifyAuthorizationCodeTokenResponseClient();

		
		FormHttpMessageConverter mockConverter = mock(FormHttpMessageConverter.class);
		
		when(mockConverter.canWrite(any(Class.class), any())).thenReturn(true);
		
		doThrow(new RuntimeException("TEST _ EXPECTED EXCEPTION")).when(mockConverter).write(any(), any(), any());
		
		RestTemplate restTemplate = new RestTemplate(Arrays.asList(mockConverter));
		
		oAuth2AccessTokenResponseClient.setRestOperations(restTemplate);

		// should throw an exception
		try {
			
			oAuth2AccessTokenResponseClient.getTokenResponse(this.caughtAuthorizationCodeGrantRequest);
			
		} catch(RuntimeException e) {
			// expected
		}
		
		ArgumentCaptor<MultiValueMap<String,?>> requestParamsMapCapt = ArgumentCaptor.forClass(MultiValueMap.class);
		
		ArgumentCaptor<HttpOutputMessage> outputMessageCapt = ArgumentCaptor.forClass(HttpOutputMessage.class);
		
		
		verify(mockConverter).write(requestParamsMapCapt.capture(), any(), outputMessageCapt.capture());
		
		
		MultiValueMap<String,?> requestParamsMap = requestParamsMapCapt.getValue();
		
		Assert.assertTrue(requestParamsMap.containsKey("client_id"));
		Assert.assertTrue(requestParamsMap.containsKey("client_secret"));
		Assert.assertTrue(requestParamsMap.containsKey("code"));
		
		
		ClientHttpRequest requestCapt = (ClientHttpRequest)outputMessageCapt.getValue();
		
		Assert.assertEquals(SHOPIFY_TOKEN_URI, requestCapt.getURI().toURL().toString());
		Assert.assertEquals(HttpMethod.POST, requestCapt.getMethod());

	}
	

}
