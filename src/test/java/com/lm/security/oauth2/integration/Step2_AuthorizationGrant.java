package com.lm.security.oauth2.integration;

import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.handler;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpSession;

import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.lm.ShopifyEmbeddedAppSpringBootApplication;
import com.lm.security.authentication.CipherPassword;
import com.lm.security.web.ShopifyHttpSessionOAuth2AuthorizationRequestRepository;


@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes= {ShopifyEmbeddedAppSpringBootApplication.class, TestConfig.class})
@AutoConfigureMockMvc
public class Step2_AuthorizationGrant {

	@Autowired
	private MockMvc mockMvc;
	
	@Autowired
	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
	
	@Autowired
	private JdbcTemplate jdbc; 
	
	@Autowired
	private CipherPassword cipherPassword;
	
	private String sessionAttributeName = HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST";
	
	private Map<String, OAuth2AuthorizationRequest> oAuth2AuthorizationRequests;
	
	/*
	 * Perform the initial Authorization request and grab objects stored in the HttpSession
	 * that will be used to "continue" the session in the test
	 */
	@SuppressWarnings("unchecked")
	@Before
	public void initializeValue() throws Exception {
		String sampleSalt = KeyGenerators.string().generateKey();
		TextEncryptor encryptor = Encryptors.queryableText(cipherPassword.getPassword(), sampleSalt);

		jdbc.update("UPDATE STOREACCESSTOKENS SET access_token=?, salt=? WHERE shop='lmdev.myshopify.com'", encryptor.encrypt("sample"), sampleSalt);
		
		MvcResult mR = this.mockMvc.perform(get("/install/shopify?shop=newstoretest.myshopify.com&timestamp=dsd&hmac=sdfasrf4324")).andReturn();

		HttpSession rSession = mR.getRequest().getSession();
		
		oAuth2AuthorizationRequests = (Map<String, OAuth2AuthorizationRequest>) rSession.getAttribute(sessionAttributeName);
		
		oAuth2AuthorizationRequests.entrySet().forEach(i -> System.out.println(i));

		
		System.out.println("Successfully initialized");
	}
	

	/* 
	 * Test OAuth2LoginAuthenticationFilter prepares a POST request 
	 * by capturing the OAuth2AuthorizationCodeGrantRequest sent to 
	 * OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
	 * 
	 * Assert that:
	 * 
	 * 1. The OAuth2AccessTokenResponseClient mock was called
	 * 2. The clientId of the ClientRegistration matches the one on TestConfig
	 * 3. The state generated in @Before(AuthorizationRequest) is in OAuth2AuthorizationRequest
	 * 4. The code passed by "Shopify" in the url is in OAuth2AuthorizationRequest
	 * 5. The redirectUri in the OAuth2AuthorizationRequest 
	 * 
	 */
	@Test
	public void whenShopifyJSRedirectsThenObtainAuthenticationCode() throws Exception {
		
		String code = "sample_code_returned_by_Shopify";
		
		// in the redirecturi, we send a nonce as state param
		Iterator<Entry<String, OAuth2AuthorizationRequest>> it = oAuth2AuthorizationRequests.entrySet().iterator();
		String state = it.next().getKey();
		System.out.println(state);
		
		MockHttpSession session = new MockHttpSession();
		System.out.println("Setting session attributes in mock: " + sessionAttributeName + " size: " + oAuth2AuthorizationRequests.size());
		session.setAttribute(sessionAttributeName, oAuth2AuthorizationRequests);
		

		
		// configure mock accessTokenResponseClient (used by OAuth2LoginAuthenticationProvider's authenticate(auth))
		// the request itself should fail
		when(accessTokenResponseClient.getTokenResponse(ArgumentMatchers.any())).thenThrow(new OAuth2AuthorizationException(new OAuth2Error("502")));
		
		this.mockMvc.perform(get("/login/app/oauth2/code/shopify?code=" + code + "&hmac=da9d83c171400a41f8db91a950508985&timestamp=1409617544&state=" + state + "&shop=newstoretest.myshopify.com").session(session)).andReturn();

		ArgumentCaptor<OAuth2AuthorizationCodeGrantRequest> grantRequest = ArgumentCaptor.forClass(OAuth2AuthorizationCodeGrantRequest.class);
		
		// ... But
		// assert...
		verify(accessTokenResponseClient).getTokenResponse(grantRequest.capture());
		
		OAuth2AuthorizationCodeGrantRequest capturedArg = grantRequest.getValue();
		ClientRegistration registration = capturedArg.getClientRegistration();
		OAuth2AuthorizationExchange authExch = capturedArg.getAuthorizationExchange();
		OAuth2AuthorizationRequest authReq = authExch.getAuthorizationRequest(); // from HttpSession
		OAuth2AuthorizationResponse authResp = authExch.getAuthorizationResponse();
		
		Pattern p = Pattern.compile(".*/login/app/oauth2/code/shopify");
		
		Assert.assertEquals("testId", registration.getClientId());
		Assert.assertEquals(state, authReq.getState());
		Assert.assertEquals(state, authResp.getState());
		Assert.assertEquals(code, authResp.getCode());
		
		Matcher matcher = p.matcher(authResp.getRedirectUri());
		Assert.assertTrue(matcher.matches());
		
		// The DefaultAuthorizationCodeTokenResponseClient takes care of preparing the POST
		
	}
	
	
	
	

}