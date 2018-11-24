package com.lm.security.oauth2.integration;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.util.UriComponentsBuilder;

import com.lm.security.web.ShopifyRedirectStrategy;


public class UtilityTest {

	@Test
	public void givenScopesListShouldReturnCorrectString() {
		List<String> scopes = Arrays.asList("read_inventory", "write_inventory", "read_products", "write_products");
		String expected = "read_inventory,write_inventory,read_products,write_products";
		
		Assert.assertEquals(expected, ShopifyRedirectStrategy.concatenateListIntoCommaString(scopes));
		
	}
	
	@Test
	public void ran() {
		String s1 = "https://newstoretest.myshopify.com/admin/oauth/authorize";
		
		String s2 = UriComponentsBuilder
		.fromUriString(s1).build().toString();
		
		Assert.assertEquals(s1, s2);
		
		
	}
	
	@Test
	public void ran2() {
		String s1 = "/oauth/authorize";
		
		String s2 = UriComponentsBuilder
		.fromUriString(s1).build().toString();
		
		Assert.assertEquals(s1, s2);
		
		
	}
	

	
	
}
