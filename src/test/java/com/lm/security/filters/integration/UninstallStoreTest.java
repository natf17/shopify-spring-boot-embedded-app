package com.lm.security.filters.integration;


import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.lm.ShopifyEmbeddedAppSpringBootApplication;
import com.lm.security.oauth2.integration.config.DisabledShopifyVerfificationConfig;
import com.lm.security.oauth2.integration.config.TestConfig;


@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes= {ShopifyEmbeddedAppSpringBootApplication.class, TestConfig.class, DisabledShopifyVerfificationConfig.class, DisableTokenService.class})
@TestPropertySource(locations="classpath:test-application.properties")
@AutoConfigureMockMvc
public class UninstallStoreTest {

	@Autowired
	private MockMvc mockMvc;
	
	@Test
	public void whenValidRequest_thenExtractBody() throws Exception {
		this.mockMvc.perform(post("/store/uninstall/shopify").content("{\"shop_id\": 954889,\"shop_domain\": \"snowdevil.myshopify.com\"}")).andExpect(status().is(200));
		
		
	}
	
	@Test
	public void whenNoStore_thenFail() throws Exception {
		this.mockMvc.perform(post("/store/uninstall/shopify").content("{\"shop_id\": 954889}")).andExpect(status().is(403));
		
		
	}
}
