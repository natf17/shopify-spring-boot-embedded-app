package com.lm.security.configuration;

import java.io.IOException;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.web.filter.CorsFilter;

import com.lm.security.filters.ShopifyExistingTokenFilter;
import com.lm.security.filters.ShopifyOriginFilter;
import com.lm.security.web.ShopifyOauth2AuthorizationRequestResolver;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.addFilterAfter(new ShopifyExistingTokenFilter(), ExceptionTranslationFilter.class);
		http.addFilterAfter(new ShopifyOriginFilter(), CorsFilter.class);
		
		http
	          .authorizeRequests()
	          	.mvcMatchers("/validate").permitAll()
	          	.anyRequest().authenticated()
	          .and()
	          .oauth2Login()
	          	.authorizationEndpoint().
	          		authorizationRequestResolver(shopifyOauth2AuthorizationRequestResolver())
	          .and().redirectionEndpoint().baseUri("/login/app/oauth2/code");
	          
	}
	
	 /* 		https://{shop}.myshopify.com/admin/oauth/authorize?
	 * 			client_id={api_key}&
	 * 			scope={scopes}&
	 * 			redirect_uri={redirect_uri}&
	 * 			state={nonce}
	 */
	@Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.shopifyClientRegistration());
    }
	
	private OAuth2AuthorizationRequestResolver shopifyOauth2AuthorizationRequestResolver() {
		return new ShopifyOauth2AuthorizationRequestResolver(clientRegistrationRepository(), "/login/app/oauth2/code");
	}
	
	private ClientRegistration shopifyClientRegistration() {
		
		return null;
		/*
        return ClientRegistration.withRegistrationId("shopify")
            .clientId("google-client-id")
            .clientSecret("google-client-secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUriTemplate("{baseUrl}/login/app/oauth2/code/{registrationId}")
            .scope("openid", "profile", "email", "address", "phone")
            .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
            .tokenUri("https://www.googleapis.com/oauth2/v4/token")
            .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
            .userNameAttributeName(IdTokenClaimNames.SUB)
            .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
            .clientName("Google")
            .build(); */
    }

	
}


