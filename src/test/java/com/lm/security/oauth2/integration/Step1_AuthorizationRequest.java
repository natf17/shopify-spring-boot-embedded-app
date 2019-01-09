package com.lm.security.oauth2.integration;

import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.handler;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.lm.ShopifyEmbeddedAppSpringBootApplication;
import com.lm.security.authentication.CipherPassword;
import com.lm.security.configuration.SecurityConfig;
import com.lm.security.oauth2.integration.config.DisabledShopifyVerfificationConfig;
import com.lm.security.oauth2.integration.config.TestConfig;


@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes= {ShopifyEmbeddedAppSpringBootApplication.class, TestConfig.class, DisabledShopifyVerfificationConfig.class})
@AutoConfigureMockMvc
public class Step1_AuthorizationRequest {

	@Autowired
	private MockMvc mockMvc;
	
	@Autowired
	private JdbcTemplate jdbc; 
	
	@Autowired
	private CipherPassword cipherPassword;
	
	private static final String INSTALL_PATH = SecurityConfig.INSTALL_PATH + "/shopify";
	
	@Before
	public void initializeValue() {
		String sampleSalt = KeyGenerators.string().generateKey();
		TextEncryptor encryptor = Encryptors.queryableText(cipherPassword.getPassword(), sampleSalt);

		jdbc.update("UPDATE STOREACCESSTOKENS SET access_token=?, salt=? WHERE shop='lmdev.myshopify.com'", encryptor.encrypt("sample"), sampleSalt);
		
	}

	@Test
	public void whenStoreExistsThenAuthenticateAndShowFirstPage() throws Exception {

	
		this.mockMvc.perform(get(INSTALL_PATH + "?shop=lmdev.myshopify.com&timestamp=dsd&hmac=sdfasrf4324"))
					.andExpect(status().is2xxSuccessful())
					.andExpect(handler().methodName("installAndHome"));
	}

	@Test
	public void whenStoreDoesNotExistThenRedirectToShopify() throws Exception {
	
		this.mockMvc.perform(get(INSTALL_PATH + "?shop=newstoretest.myshopify.com&timestamp=dsd&hmac=sdfasrf4324"))
					.andExpect(content().string(containsString("var redirectFromParentPath = 'https://newstoretest.myshopify.com/admin/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")))
					.andExpect(content().string(containsString("var redirectFromIFramePath = '/oauth/authorize?client_id=testId&redirect_uri=https://localhost/login/app/oauth2/code/shopify&scope=read_inventory,write_inventory,read_products,write_products&state=")));
	}

	
	
	
	
	

}