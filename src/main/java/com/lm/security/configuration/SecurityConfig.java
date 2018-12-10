package com.lm.security.configuration;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import com.lm.security.authentication.CipherPassword;
import com.lm.security.filters.ShopifyExistingTokenFilter;
import com.lm.security.filters.ShopifyOriginFilter;
import com.lm.security.service.DefaultShopifyUserService;
import com.lm.security.service.ShopifyOAuth2AuthorizedClientService;
import com.lm.security.service.TokenService;
import com.lm.security.web.NoRedirectSuccessHandler;
import com.lm.security.web.ShopifyAuthorizationCodeTokenResponseClient;
import com.lm.security.web.ShopifyOAuth2AuthorizationRequestResolver;


@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	public static final String INSTALL_PATH = "/install";
	public static final String ANY_INSTALL_PATH = INSTALL_PATH + "/**";
	public static final String AUTHORIZATION_REDIRECT_PATH = "/login/app/oauth2/code";
	public static final String ANY_AUTHORIZATION_REDIRECT_PATH = AUTHORIZATION_REDIRECT_PATH + "/**";
		

	@Autowired
	ApplicationContext ctx;
	
	
	@Autowired
	private TokenService tokenService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		System.out.println(this.tokenService.toString());

		
		Object bean = ctx.getBean("shopifyOauth2AuthorizationRequestResolver");
		

		http.addFilterAfter(new ShopifyOriginFilter(ANY_AUTHORIZATION_REDIRECT_PATH, ANY_INSTALL_PATH), LogoutFilter.class);
		http.addFilterAfter(new ShopifyExistingTokenFilter(this.tokenService, ANY_INSTALL_PATH), ShopifyOriginFilter.class);
		
		http
	          .authorizeRequests()
	          	.mvcMatchers(ANY_AUTHORIZATION_REDIRECT_PATH, ANY_INSTALL_PATH).permitAll()
	          	.anyRequest().authenticated()
	          .and()
	          .oauth2Login()
	          	.authorizationEndpoint()
	          		.authorizationRequestResolver((OAuth2AuthorizationRequestResolver)bean)
	          .and()
	          	.redirectionEndpoint().baseUri(ANY_AUTHORIZATION_REDIRECT_PATH) // same as filterProcessesUrl
	          .and()
	          	.tokenEndpoint().accessTokenResponseClient(accessTokenResponseClient()) // allows for seamless unit testing
	          .and()
	          	.userInfoEndpoint().userService(userService())
	          .and()
	          	.successHandler(successHandler())
	          	.loginPage(INSTALL_PATH); // NOT for embedded app, since it involves a redirect, it wouldn't be in the embedded app scenario
	          
	}
	

	@Bean
	CipherPassword cipherPassword(@Value("${lm.security.cipher.password}") String password) {
		return new CipherPassword(password);
	}
	
	
	@Bean
	OAuth2UserService<OAuth2UserRequest, OAuth2User> userService() {
		return new DefaultShopifyUserService();
	}
	
	
	@Bean
	public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
		return new ShopifyAuthorizationCodeTokenResponseClient();
	}
	
	
	@Bean
	public AuthenticationSuccessHandler successHandler() {
		return new NoRedirectSuccessHandler();
	}
	
	
	@Bean
    public ClientRegistrationRepository clientRegistrationRepository(ClientRegistration shopifyClientRegistration) {
        return new InMemoryClientRegistrationRepository(shopifyClientRegistration);
    }
	
	// used by AuthenticatedPrincipalOAuth2AuthorizedClientRepository
	@Bean
	public OAuth2AuthorizedClientService clientService() {
		return new ShopifyOAuth2AuthorizedClientService(this.tokenService);
	}
	
	@Bean(name="shopifyOauth2AuthorizationRequestResolver")
	public OAuth2AuthorizationRequestResolver shopifyOauth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository) {
		return new ShopifyOAuth2AuthorizationRequestResolver(clientRegistrationRepository, INSTALL_PATH);
	}
	

	@Bean
	protected ClientRegistration shopifyClientRegistration(@Value("${shopify.client.client_id}")String clientId,
			 @Value("${shopify.client.client_secret}")String clientSecret, 
			 @Value("${shopify.client.scope}")String scope) {
		

        return ClientRegistration.withRegistrationId("shopify")
            .clientId(clientId)
            .clientSecret(clientSecret)
            .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUriTemplate("{baseUrl}" + AUTHORIZATION_REDIRECT_PATH + "{registrationId}")
            .scope(scope.split(","))
            .authorizationUri("https://{shop}/admin/oauth/authorize")
            .tokenUri("https://{shop}/admin/oauth/access_token")
            .clientName("Shopify")
            .build();
    }


	
	

}


