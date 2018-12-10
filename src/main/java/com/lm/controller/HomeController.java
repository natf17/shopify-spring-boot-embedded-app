package com.lm.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.lm.security.configuration.SecurityConfig;

@Controller
public class HomeController {
	
	/*
	 * This controller can be reached via different scenarios:
	 * 
	 * 1. Authenticated: Shopify made the request and the store had already installed the app (embedded app scenario)
	 * ... or the request did not come from Shopify but a store param was included (let Shopify log the user in)
	 * 
	 * 2. Anonymous: User makes a request (not as an embedded app) without providing anything store param
	 * 
	 */
	
	@RequestMapping(path = SecurityConfig.ANY_INSTALL_PATH, method = RequestMethod.GET)
	public String installAndHome() {
		
				
		return "home";
	}
	
	@RequestMapping(path =SecurityConfig.ANY_AUTHORIZATION_REDIRECT_PATH, method = RequestMethod.GET)
	public String installationSuccess() {
		
				
		return "success";
	}

}
