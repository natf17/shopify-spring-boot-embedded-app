package com.lm.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class HomeController {
	
	@RequestMapping(path = "/install/*", method = RequestMethod.GET)
	public String installAndHome() {
		System.out.println(SecurityContextHolder.getContext().getAuthentication());

		System.out.println("Showing default home page");
		
		return "home";
	}

}
