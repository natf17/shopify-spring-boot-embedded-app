package com.lm.security.authentication;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.digest.DigestUtils;
import org.junit.Before;
import org.junit.Test;

import org.junit.Assert;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

public class ShopifyVerificationStrategyTest {
	
	private HttpServletRequest req;
	
	private ShopifyVerificationStrategy strategy = new ShopifyVerificationStrategy(null);
	
	@Before
	public void startup() {
		req = mock(HttpServletRequest.class);
		
	}
	
	@Test
	public void validHMACRandomReturnsTrue() {
		String stringNoHMAC = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
		String hmacValue = DigestUtils.sha256Hex(stringNoHMAC);
		String hmacString = ShopifyVerificationStrategy.HMAC_PARAMETER + "=" + hmacValue + "&";

		String validCompleteString = "code=fsv&" + hmacString + "shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
		
		when(req.getQueryString()).thenReturn(validCompleteString);
		
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {hmacValue});
		
		
		when(req.getParameterMap()).thenReturn(paramMap);
		
		Assert.assertEquals(true, this.strategy.isShopifyRequest(req));
		
		
	}
	
	@Test
	public void validHMACLastReturnsTrue() {
		String stringNoHMAC = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
		String hmacValue = DigestUtils.sha256Hex(stringNoHMAC);
		String hmacString = "&" + ShopifyVerificationStrategy.HMAC_PARAMETER + "=" + hmacValue;

		String validCompleteString = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173" + hmacString;
		
		when(req.getQueryString()).thenReturn(validCompleteString);
		
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {hmacValue});
		
		
		when(req.getParameterMap()).thenReturn(paramMap);
		
		Assert.assertEquals(true, this.strategy.isShopifyRequest(req));
		
		
	}
	
	
	@Test
	public void invalidHMACLastReturnsFalse() {
		String stringNoHMAC = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
		String hmacValue = DigestUtils.sha256Hex(stringNoHMAC) + "asd";
		String hmacString = "&" + ShopifyVerificationStrategy.HMAC_PARAMETER + "=" + hmacValue;

		String validCompleteString = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173" + hmacString;
		
		when(req.getQueryString()).thenReturn(validCompleteString);
		
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {hmacValue});
		
		
		when(req.getParameterMap()).thenReturn(paramMap);
		
		Assert.assertEquals(false, this.strategy.isShopifyRequest(req));
		
		
	}
	
	@Test
	public void noHMACReturnsFalse() {
		String stringNoHMAC = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
		
		when(req.getQueryString()).thenReturn(stringNoHMAC);
		
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put("code", new String[] {"fsv"});
		
		
		when(req.getParameterMap()).thenReturn(paramMap);
		
		Assert.assertEquals(false, this.strategy.isShopifyRequest(req));
		
		
	}
	
	@Test
	public void multipleHMACReturnsFalse() {
		String stringNoHMAC = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
		String hmacValue = DigestUtils.sha256Hex(stringNoHMAC) + "asd";
		String hmacString = "&" + ShopifyVerificationStrategy.HMAC_PARAMETER + "=" + hmacValue;

		String validCompleteString = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173" + hmacString + hmacString;
		
		when(req.getQueryString()).thenReturn(validCompleteString);
		
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {hmacValue});
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {hmacValue});
		
		
		when(req.getParameterMap()).thenReturn(paramMap);
		
		Assert.assertEquals(false, this.strategy.isShopifyRequest(req));
		
		
		
	}
	
	

}
