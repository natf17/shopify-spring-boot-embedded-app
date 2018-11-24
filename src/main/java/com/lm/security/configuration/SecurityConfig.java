package com.lm.security.configuration;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.filter.CorsFilter;

import com.lm.security.authentication.CipherPassword;
import com.lm.security.filters.ShopifyExistingTokenFilter;
import com.lm.security.filters.ShopifyOriginFilter;
import com.lm.security.service.TokenService;
import com.lm.security.web.ShopifyAuthorizationCodeTokenResponseClient;
import com.lm.security.web.ShopifyOauth2AuthorizationRequestResolver;


@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private TokenService tokenService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.addFilterAfter(new ShopifyOriginFilter(), LogoutFilter.class);
		http.addFilterAfter(new ShopifyExistingTokenFilter(this.tokenService, "/install/**"), ShopifyOriginFilter.class);
		//http.addFilterBefore(new TestFilter(), OAuth2LoginAuthenticationFilter.class);
		
		http
	          .authorizeRequests()
	          	.mvcMatchers("/login/app/oauth2/code/**").permitAll()
	          	.anyRequest().authenticated()
	          .and()
	          .oauth2Login()
	          	.authorizationEndpoint()
	          		.authorizationRequestResolver(shopifyOauth2AuthorizationRequestResolver())
	          .and()
	          	.redirectionEndpoint().baseUri("/login/app/oauth2/code/**")
	          .and()
	          	.tokenEndpoint().accessTokenResponseClient(accessTokenResponseClient()); // allows for seamless unit testing
	          
	}
	

	@Bean
	CipherPassword cipherPassword(@Value("${lm.security.cipher.password}") String password) {
		return new CipherPassword(password);
	}
	

	
	@Bean
	public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
		return new ShopifyAuthorizationCodeTokenResponseClient();
	}
	
	
	@Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.shopifyClientRegistration());
    }
	
	
	private OAuth2AuthorizationRequestResolver shopifyOauth2AuthorizationRequestResolver() {
		return new ShopifyOauth2AuthorizationRequestResolver(clientRegistrationRepository(), "/install");
	}
	
	private ClientRegistration shopifyClientRegistration() {
		

        return ClientRegistration.withRegistrationId("shopify")
            .clientId("zz")
            .clientSecret("zz")
            .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUriTemplate("{baseUrl}/login/app/oauth2/code/{registrationId}")
            .scope("read_inventory", "write_inventory", "read_products", "write_products")
            .authorizationUri("https://{shop}/admin/oauth/authorize")
            .tokenUri("https://{shop}/admin/oauth/access_token")
            .clientName("Shopify")
            .build();
    }
	/*
	private class TestFilter implements Filter {

		@Override
		public void doFilter(ServletRequest req, ServletResponse res, FilterChain fc)
				throws IOException, ServletException {
			System.out.println("About to call OAuth2LoginAuthenticationFilter: " + ((HttpServletRequest)req).getRequestURI() + " with state: " + req.getParameter("state"));
			Map<String, OAuth2AuthorizationRequest> authorizationRequests = this.getAuthorizationRequests((HttpServletRequest)req);
			
			System.out.println(authorizationRequests.size());
			try {
				fc.doFilter(req, res);
			} catch(Exception ex) {
				System.out.println("******* CAUGHT EXCEPTION ******");
				System.out.println(ex.getClass());
				System.out.println(ex.getMessage());
				System.out.println(ex.getStackTrace());
			}
			
		}
		
		@SuppressWarnings("unchecked")
		private Map<String, OAuth2AuthorizationRequest> getAuthorizationRequests(HttpServletRequest request) {
			HttpSession session = request.getSession(false);
			Map<String, OAuth2AuthorizationRequest> authorizationRequests = session == null ? null :
					(Map<String, OAuth2AuthorizationRequest>) session.getAttribute(HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST");
			if (authorizationRequests == null) {
				return new HashMap<>();
			}
			return authorizationRequests;
		}
		
	}
	
	*/

}


