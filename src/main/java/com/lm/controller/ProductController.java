package com.lm.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;


@Controller
public class ProductController {
	
	@RequestMapping(path = "/products", method = RequestMethod.GET)
	public String products() {
		
				
		return "products";
	}

}
