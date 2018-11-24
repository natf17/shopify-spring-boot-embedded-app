package com.lm.security.oauth2.integration;

import static org.hamcrest.CoreMatchers.containsString;
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
import java.util.Map;

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
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
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
public class Step1_AuthorizationRequest {

	@Autowired
	private MockMvc mockMvc;
	
	@Autowired
	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;
	
	@Autowired
	private JdbcTemplate jdbc; 
	
	@Autowired
	private CipherPassword cipherPassword;
	
	@Before
	public void initializeValue() {
		String sampleSalt = KeyGenerators.string().generateKey();
		TextEncryptor encryptor = Encryptors.queryableText(cipherPassword.getPassword(), sampleSalt);

		jdbc.update("UPDATE STOREACCESSTOKENS SET access_token=?, salt=? WHERE shop='lmdev.myshopify.com'", encryptor.encrypt("sample"), sampleSalt);
		
		System.out.println("Successfully initialized");
	}

	@Test
	public void whenStoreExistsThenAuthenticateAndShowFirstPage() throws Exception {
		System.out.println("1st TEST");

	
		this.mockMvc.perform(get("/install/shopify?shop=lmdev.myshopify.com&timestamp=dsd&hmac=sdfasrf4324"))
					.andExpect(status().is2xxSuccessful())
					.andExpect(handler().methodName("installAndHome"));
	}
	


	@Test
	public void whenStoreDoesNotExistThenRedirectToShopify() throws Exception {
		System.out.println("2nd TEST");
	
		this.mockMvc.perform(get("/install/shopify?shop=newstoretest.myshopify.com&timestamp=dsd&hmac=sdfasrf4324"))
					.andExpect(content().string(containsString("var redirectFromParentPath = 'https://newstoretest.myshopify.com/admin/oauth/authorize?client_id=testId&redirect_uri=http://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=nonce'")))
					.andExpect(content().string(containsString("var redirectFromIFramePath = '/oauth/authorize?client_id=testId&redirect_uri=http://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=nonce'")));
	}
	
	
	

}