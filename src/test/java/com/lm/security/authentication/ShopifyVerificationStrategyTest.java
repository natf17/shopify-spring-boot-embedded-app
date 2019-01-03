package com.lm.security.authentication;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;

import org.junit.Assert;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doReturn;

import java.util.HashMap;
import java.util.Map;

public class ShopifyVerificationStrategyTest {
	
	private HttpServletRequest req;
	
	private String secret = "6a031b0bd6af4eb";
	
	@Before
	public void startup() {
		
	}
	
	@Test
	public void validHMACRandomReturnsTrue() {
		// string without HMAC
		String stringNoHMAC = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
		
		ShopifyVerificationStrategy strategy = spy(new ShopifyVerificationStrategy(null,null));

		// The hash of the string without the HMAC
		String hmacValue = strategy.hash(secret, stringNoHMAC);
		
		// The query piece with the valid HMAC
		String hmacString = ShopifyVerificationStrategy.HMAC_PARAMETER + "=" + hmacValue + "&";

		// The full query string
		String validCompleteString = "code=fsv&" + hmacString + "shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
		
		// The HttpServletRequest has the valid HMAC parameter
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {hmacValue});
		
		req = mock(HttpServletRequest.class);

		when(req.getQueryString()).thenReturn(validCompleteString);
		when(req.getParameterMap()).thenReturn(paramMap);


		// calling getClientSecret in the strategy will always return a valid secret
		doReturn(secret).when(strategy).getClientSecret(any());

		
		Assert.assertEquals(true, strategy.isShopifyRequest(req));
		
		
	}
	
	@Test
	public void validHMACLastReturnsTrue() {
		
		// string without HMAC
		String stringNoHMAC = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
		
		ShopifyVerificationStrategy strategy = spy(new ShopifyVerificationStrategy(null,null));

		// The hash of the string without the HMAC
		String hmacValue = strategy.hash(secret, stringNoHMAC);
		
		// The query piece with the valid HMAC
		String hmacString = "&" + ShopifyVerificationStrategy.HMAC_PARAMETER + "=" + hmacValue;

		// The full query string
		String validCompleteString = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173" + hmacString;
		
		// The HttpServletRequest has the valid HMAC parameter
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {hmacValue});
		
		req = mock(HttpServletRequest.class);

		when(req.getQueryString()).thenReturn(validCompleteString);
		when(req.getParameterMap()).thenReturn(paramMap);


		// calling getClientSecret in the strategy will always return a valid secret
		doReturn(secret).when(strategy).getClientSecret(any());

		
		Assert.assertEquals(true, strategy.isShopifyRequest(req));

		
		
	}
	

	
	@Test
	public void invalidHMACLastReturnsFalse() {
		
		
		// string without HMAC
		String stringNoHMAC = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
		
		ShopifyVerificationStrategy strategy = spy(new ShopifyVerificationStrategy(null,null));

		// The wrong hash of the string without the HMAC
		String hmacValue = strategy.hash(secret, stringNoHMAC) + "asd";
		
		// The query piece with the valid HMAC
		String hmacString = "&" + ShopifyVerificationStrategy.HMAC_PARAMETER + "=" + hmacValue;

		// The full query string
		String validCompleteString = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173" + hmacString;
		
		// The HttpServletRequest has the valid HMAC parameter
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {hmacValue});
		
		req = mock(HttpServletRequest.class);

		when(req.getQueryString()).thenReturn(validCompleteString);
		when(req.getParameterMap()).thenReturn(paramMap);


		// calling getClientSecret in the strategy will always return a valid secret
		doReturn(secret).when(strategy).getClientSecret(any());

		
		Assert.assertEquals(false, strategy.isShopifyRequest(req));

		
	}
	
	
	
	@Test
	public void noHMACReturnsFalse() {
		
		// string without HMAC
		String stringNoHMAC = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
		
		ShopifyVerificationStrategy strategy = spy(new ShopifyVerificationStrategy(null,null));

		
		// The HttpServletRequest has some other parameter
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put("code", new String[] {"fsv"});
		
		req = mock(HttpServletRequest.class);

		when(req.getQueryString()).thenReturn(stringNoHMAC);
		when(req.getParameterMap()).thenReturn(paramMap);


		// calling getClientSecret in the strategy will always return a valid secret
		doReturn(secret).when(strategy).getClientSecret(any());

		
		Assert.assertEquals(false, strategy.isShopifyRequest(req));
		
		
	}
	
	@Test
	public void multipleHMACReturnsFalse() {
		
		// string without HMAC
		String stringNoHMAC = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173";
		
		ShopifyVerificationStrategy strategy = spy(new ShopifyVerificationStrategy(null,null));

		// The hash of the string without the HMAC
		String hmacValue = strategy.hash(secret, stringNoHMAC);
		
		// The query piece with the valid HMAC
		String hmacString = "&" + ShopifyVerificationStrategy.HMAC_PARAMETER + "=" + hmacValue;

		// The full query string with multiple HMACs
		String validCompleteString = "code=fsv&shop=some-shop.myshopify.com&state=0.6784241404160823&timestamp=1337178173" + hmacString + hmacString;
		
		// The HttpServletRequest has multiple valid HMAC parameters
		Map<String, String[]> paramMap = new HashMap<>();
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {hmacValue});
		paramMap.put(ShopifyVerificationStrategy.HMAC_PARAMETER, new String[] {hmacValue});

		
		req = mock(HttpServletRequest.class);

		when(req.getQueryString()).thenReturn(validCompleteString);
		when(req.getParameterMap()).thenReturn(paramMap);


		// calling getClientSecret in the strategy will always return a valid secret
		doReturn(secret).when(strategy).getClientSecret(any());

		
		Assert.assertEquals(false, strategy.isShopifyRequest(req));
		
		
	}
	
	@Test
	public void givenInvalidBodyThenIsHeaderShopifyRequestMustFail() {
		ShopifyVerificationStrategy strategy = new ShopifyVerificationStrategy(null, null);
		String body = "{\"id\":689034}";
		
		String hmac = strategy.hash(this.secret, body);

		Assert.assertFalse(strategy.isShopifyHeaderRequest(body + "ds", hmac, secret));
	}
	
	@Test
	public void givenValidBodyThenIsHeaderShopifyRequestMustPass() {
		ShopifyVerificationStrategy strategy = new ShopifyVerificationStrategy(null, null);
		String body = "{\"id\":689034}";
		
		String hmac = strategy.hash(this.secret, body);

		Assert.assertFalse(strategy.isShopifyHeaderRequest(body, hmac, this.secret));
	}
	
	@Test
	public void givenValidRequestThenIsHeaderShopifyRequestIsTrue() {
		ShopifyVerificationStrategy strategy = spy(new ShopifyVerificationStrategy(null, null));
		
		String body = "{\"id\":689034}";
		String secret = "dfdfbjhew";
		
		String hmac = strategy.hash(secret, body);
		
		HttpServletRequest request = mock(HttpServletRequest.class);
		
		when(request.getAttribute("X-Shopify-Hmac-SHA256")).thenReturn(hmac);
		doReturn(body).when(strategy).getBody(any());
		doReturn(secret).when(strategy).getClientSecretByRegistrationId(any());
		
		strategy.isHeaderShopifyRequest(request, "registrationId");
	}
	
	
	@Test
	public void givenInvalidRequestThenIsHeaderShopifyRequestIsTrue() {
		
		ShopifyVerificationStrategy strategy = spy(new ShopifyVerificationStrategy(null, null));
		
		String body = "{\"id\":689034}" + "sad";
		String secret = "dfdfbjhew";
		
		String hmac = strategy.hash(secret, body);
		
		HttpServletRequest request = mock(HttpServletRequest.class);
		
		when(request.getAttribute("X-Shopify-Hmac-SHA256")).thenReturn(hmac);
		doReturn(body).when(strategy).getBody(any());
		doReturn(secret).when(strategy).getClientSecretByRegistrationId(any());
		
		strategy.isHeaderShopifyRequest(request, "registrationId");
		
	}

}
