package com.lm.security.filters;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;

import org.junit.Assert;
import org.junit.Test;

import com.lm.security.configuration.SecurityConfig;

public class UninstallFilterTest {
		
	@Test
	public void whenCalled_thenSuccessfulMatch() {
		String url = SecurityConfig.UNINSTALL_URI + "/shopify";
		
		UninstallFilter filter = new UninstallFilter(SecurityConfig.UNINSTALL_URI, null, null, null);
		
		HttpServletRequest req = mock(HttpServletRequest.class);
		when(req.getServletPath()).thenReturn("");
		when(req.getPathInfo()).thenReturn(url);
		
		Assert.assertEquals("shopify", filter.matches(req));
	}
	

}
