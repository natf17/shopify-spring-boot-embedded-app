package com.lm.security.filters.integration;

import static org.mockito.Mockito.mock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import com.lm.security.service.TokenService;

@Configuration
public class DisableTokenService {

	@Bean
	@Primary
	public TokenService tokenService() {
		return mock(TokenService.class);
	}
}
