package com.lm.security.oauth2.integration;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.lm.ShopifyEmbeddedAppSpringBootApplication;
import com.lm.security.authentication.CipherPassword;
import com.lm.security.web.ShopifyAuthorizationCodeTokenResponseClient;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes= {ShopifyEmbeddedAppSpringBootApplication.class, TestConfig.class})
@AutoConfigureMockMvc
public class Step3_AccessToken {
	
	
	
	
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
	
	private OAuth2AuthorizationCodeGrantRequest caughtAuthorizationCodeGrantRequest;

	
	
	/*
	 * Capture the OAuth2AuthorizationCodeGrantRequest passed into OAuth2AccessTokenResponseClient.getTokenResponse(...)
	 * (OAuth2AccessTokenResponseClient would be DefaultAuthorizationCodeTokenResponseClient, but is a mock in the test)
	 * 
	 */
	
	
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
		
		
		// part 1
		MvcResult mR = this.mockMvc.perform(get("/install/shopify?shop=newstoretest.myshopify.com&timestamp=dsd&hmac=sdfasrf4324")).andReturn();

		HttpSession rSession = mR.getRequest().getSession();
		
		oAuth2AuthorizationRequests = (Map<String, OAuth2AuthorizationRequest>) rSession.getAttribute(sessionAttributeName);
		
		oAuth2AuthorizationRequests.entrySet().forEach(i -> System.out.println(i));

		
		System.out.println("Successfully initialized");
		
		
		// part 2
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
		

		verify(accessTokenResponseClient).getTokenResponse(grantRequest.capture());
		
		
		
		
		// capture the OAuth2AuthorizationCodeGrantRequest
		caughtAuthorizationCodeGrantRequest = grantRequest.getValue();
		System.out.println("-----captured caughtAuthorizationCodeGrantRequest");
		
		
		
	}
	
	
	
	
	
	
	
	/*
	
	@Test
	public void given_OAuth2AuthorizationCodeGrantRequest_Then_DefaultAuthorizationCodeTokenResponseClient_Returns_Valid_OAuth2AccessTokenResponse() throws Exception {
		ShopifyAuthorizationCodeTokenResponseClient oAuth2AccessTokenResponseClient = new ShopifyAuthorizationCodeTokenResponseClient();
		
		
		// default:
		RestTemplate restTemplate = new RestTemplate(Arrays.asList(
				new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()));
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
		
		
		// set a mock ClientHttpRequestFactory
		// that returns a mock ClientHttpRequest whose execute() will always return ... ClientHttpResponse
		ClientHttpRequestFactory mockFactory = mock(ClientHttpRequestFactory.class);
		ClientHttpRequest mockRequest = mock(ClientHttpRequest.class);
		ClientHttpResponse mockResponse = mock(ClientHttpResponse.class);
		HttpHeaders responseHeaders = new HttpHeaders();
		responseHeaders.add(HttpHeaders.CONTENT_TYPE, "application/json");
		InputStream is = new ByteArrayInputStream("{\"access_token\": \"f85632530bf277ec9ac6f649fc327f17\",\"scope\": \"write_orders,read_customers\"}".getBytes(StandardCharsets.UTF_8));
		when(mockResponse.getBody()).thenReturn(is);
		when(mockResponse.getHeaders()).thenReturn(responseHeaders);
		
		
		when(mockRequest.execute()).thenReturn(mockResponse);
		when(mockRequest.getHeaders()).thenReturn(new HttpHeaders());
		when(mockRequest.getBody()).thenReturn(new ByteArrayOutputStream());
		
		when(mockFactory.createRequest(any(), any())).thenReturn(mockRequest);
		
		restTemplate.setRequestFactory(mockFactory);
		
		oAuth2AccessTokenResponseClient.setRestOperations(restTemplate);
		
		
		OAuth2AccessTokenResponse resp = oAuth2AccessTokenResponseClient.getTokenResponse(this.caughtAuthorizationCodeGrantRequest);
		
		Assert.assertEquals("f85632530bf277ec9ac6f649fc327f17", resp.getAccessToken().getTokenValue());
		
		
	}
	
	*/
	
	// will it generate a valid request object?
	/*
	 * url: 
	 * 
	 * body: 
	 * 
	 * client_id: The API key for the app, as defined in the Partner Dashboard.
	 * client_secret: The API secret key for the app, as defined in the Partner Dashboard.
	 * code: ...
	 */
	
	@SuppressWarnings("unchecked")
	@Test
	public void given_OAuth2AuthorizationCodeGrantRequest_Then_DefaultAuthorizationCodeTokenResponseClient_Returns_Valid_OAuth2AccessTokenResponse() throws Exception {
		ShopifyAuthorizationCodeTokenResponseClient oAuth2AccessTokenResponseClient = new ShopifyAuthorizationCodeTokenResponseClient();
		
		
		/* default:
		RestTemplate restTemplate = new RestTemplate(Arrays.asList(
				new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()));
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
		*/
		
		// set a mock ClientHttpRequestFactory
		// that returns a mock ClientHttpRequest whose execute() will always return ... ClientHttpResponse
		
		
		
		
		FormHttpMessageConverter mockConverter = mock(FormHttpMessageConverter.class);
		when(mockConverter.canWrite(any(Class.class), any())).thenReturn(true);
		doThrow(new RuntimeException("TEST _ EXPECTED EXCEPTION")).when(mockConverter).write(any(), any(), any());
		
		RestTemplate restTemplate = new RestTemplate(Arrays.asList(mockConverter));
		
		oAuth2AccessTokenResponseClient.setRestOperations(restTemplate);

		// should throw an exception
		try { 
			OAuth2AccessTokenResponse resp = oAuth2AccessTokenResponseClient.getTokenResponse(this.caughtAuthorizationCodeGrantRequest);
		} catch(RuntimeException e) {
			// expected
		}
		ArgumentCaptor<MultiValueMap<String,?>> requestParamsMapCapt = ArgumentCaptor.forClass(MultiValueMap.class);

		verify(mockConverter).write(requestParamsMapCapt.capture(), any(), any());
		
		MultiValueMap<String,?> requestParamsMap = requestParamsMapCapt.getValue();
		Assert.assertTrue(requestParamsMap.containsKey("client_id"));
		Assert.assertTrue(requestParamsMap.containsKey("client_secret"));
		Assert.assertTrue(requestParamsMap.containsKey("code"));

		
		/*
		ClientHttpRequestFactory mockFactory = mock(ClientHttpRequestFactory.class);
		ClientHttpRequest mockRequest = mock(ClientHttpRequest.class);
		ClientHttpResponse mockResponse = mock(ClientHttpResponse.class);
		HttpHeaders responseHeaders = new HttpHeaders();
		responseHeaders.add(HttpHeaders.CONTENT_TYPE, "application/json");
		InputStream is = new ByteArrayInputStream("{\"access_token\": \"f85632530bf277ec9ac6f649fc327f17\",\"scope\": \"write_orders,read_customers\"}".getBytes(StandardCharsets.UTF_8));
		when(mockResponse.getBody()).thenReturn(is);
		when(mockResponse.getHeaders()).thenReturn(responseHeaders);
		
		
		when(mockRequest.execute()).thenReturn(mockResponse);
		when(mockRequest.getHeaders()).thenReturn(new HttpHeaders());
		when(mockRequest.getBody()).thenReturn(new ByteArrayOutputStream());
		
		when(mockFactory.createRequest(any(), any())).thenReturn(mockRequest);
		
		restTemplate.setRequestFactory(mockFactory);
		
		
		
		// correct request:
		// destination
		// post
		// 
		oAuth2AccessTokenResponseClient.setRestOperations(restTemplate);
		
		
		OAuth2AccessTokenResponse resp = oAuth2AccessTokenResponseClient.getTokenResponse(this.caughtAuthorizationCodeGrantRequest);
		
		Assert.assertEquals("f85632530bf277ec9ac6f649fc327f17", resp.getAccessToken().getTokenValue());
		
		*/
	}

}
