package com.louismartin;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.lm.ShopifyEmbeddedAppSpringBootApplication;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes= ShopifyEmbeddedAppSpringBootApplication.class)
@AutoConfigureMockMvc
public class ShopifyEmbeddedAppSpringBootApplicationTests {

	@Autowired
	private MockMvc mockMvc;
	
	@Test
	public void whenInstalledRedirectToShopify() throws Exception {

	
		this.mockMvc.perform(get("/install/shopify?shop=lmdev.myshopify.com&timestamp=dsd&hmac=sdfasrf4324"))
					.andExpect(status().is3xxRedirection())
					.andExpect(redirectedUrl("https://lmdev.myshopify.com/admin/oauth/authorize?"));
	}

}