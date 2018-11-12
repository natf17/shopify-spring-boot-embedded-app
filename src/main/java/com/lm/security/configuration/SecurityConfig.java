package com.lm.security.configuration;

import java.io.IOException;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.filter.CorsFilter;

import com.lm.security.filters.ShopifyExistingTokenFilter;
import com.lm.security.filters.ShopifyOriginFilter;
import com.lm.security.service.TokenService;
import com.lm.security.web.ShopifyOauth2AuthorizationRequestResolver;


@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.addFilterAfter(new ShopifyExistingTokenFilter("/install/**"), ExceptionTranslationFilter.class);
		http.addFilterAfter(new ShopifyOriginFilter(), ShopifyExistingTokenFilter.class);
		
		http
	          .authorizeRequests()
	          	.mvcMatchers("/login/app/oauth2/code").permitAll()
	          	.anyRequest().authenticated()
	          .and()
	          .oauth2Login()
	          	.authorizationEndpoint()
	          		.authorizationRequestResolver(shopifyOauth2AuthorizationRequestResolver())
	          .and()
	          	.redirectionEndpoint().baseUri("/login/app/oauth2/code");
	          
	}
	

	@Bean
	BytesEncryptor bytesEncryptor(@Value("${lm.security.cipher.password}") String password) {
    
		String salt = KeyGenerators.string().generateKey(); // generates a random 8-byte salt that is then hex-encoded
    
		BytesEncryptor bytesEncryptor = Encryptors.standard(password, salt);
    
		return bytesEncryptor;
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
		

        return ClientRegistration.withRegistrationId("shopify")
            .clientId("zz")
            .clientSecret("zz")
            .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUriTemplate("{baseUrl}/login/app/oauth2/code/{registrationId}")
            .scope("read_inventory", "write_inventory", "read_products", "write_products")
            .authorizationUri("https://{shop}.myshopify.com/admin/oauth/authorize")
            .clientName("Shopify")
            .build();
    }

}


