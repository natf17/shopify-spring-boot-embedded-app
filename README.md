# Getting started
***************************************

How can we use Shopify's default OAuth offline access token in a Spring Boot app, leveraging the power of Spring Security? This working implementation only requires a few lines in the application.properties file for it to work. It is a server that authenticates with Shopify and, upon successful authentication, keeps the OAuth token, store name, and api key in a session object, which can be used in a variety of ways, such as a single page web application (or React/Polaris).

We assume you know your way around the Shopify developer site to create apps and development stores. Once you have a development store, create a private app.

1. Copy the API key and API key secret from the Shopify site.
2. Store them, along with the desired scope, in the application.properties:

```
shopify.client.client_id={your key}
shopify.client.client_secret={your key secret}
shopify.client.scope={scope1,scope2,...}
```
3. Choose the salt and password that the Spring encryptors will use to encrypt the token and add them to your application.properties:

```
lm.security.cipher.password={your password}
lm.security.cipher.salt={your salt}
```

4. Whether you're using ngrok, or your own server, make sure you use HTTPS to comply with Shopify's security requirements. 

5. Add the following information to your app on Shopify:
	- App url: https://{hostname}/install/shopify
	- Whitelisted redirection urls: https://{hostname}/login/app/oauth2/code/shopify

6. That's it!

Try out the following URIs:
- `/install/shopify?shop={your store}`: to log in
- `/init`: to log in by entering your store in a form
- `/products`: a secure endpoint
- `/logout`: to log out

You can change the defaults in the `SecurityConfig` class in the `com.lm.security.configuration` package.



Note: This Spring Security application requires the Java Cryptography Encryption policy files for encryption.

See https://www.oracle.com/technetwork/java/javase/downloads/jce-all-download-5170447.html

***************************************

# Under the hood
***************************************


### `ShopifyOriginFilter`
- This filter makes sure the request possesses the necessary information to verify the request came from Shopify by checking for:
	1. Checking the HMAC (/install/** and /login/app/oauth2/code/**)
	2. A valid nonce (/login/app/oauth2/code/**)
- If the request is to the application installation path (/install/**), this filter sets a `ShopifyOriginToken` as the `Authentication` object if it is determined that the request came from Shopify (and if there is no `OAuth2Token` authentication object already). If it comes from Shopify, this is an embedded app. A session attribute is added ("SHOPIFY_EMBEDDED_APP", true) to note this.
- If the request is to what Shopify calls the "whitelisted redirection url" (/login/app/oauth2/code/**), the request MUST come from Shopify. Otherwise, a 403 response is sent via the `AccessDeniedHandler`.
- See `ShopifyVerificationStrategy` for how it is determined that a request came from Shopify

### `ShopifyExistingTokenFilter`
- This filter matches the installation endpoint path (/install/shopify).
- If there is a `ShopifyOriginToken` as the `Authentication`, attempt to replace it with a `OAuth2AuthenticationToken` using the `OAuth2AuthorizedClient` retrieved from the `TokenService`. This will be successful only if this store has already been installed. As a side note, the only way this path can be reached with an `ShopifyOriginToken` is in the embedded app scenario, where Shopify itself invokes the installation uri.
- If none exists (the store has not been installed as an embedded app or this call is coming as a regular request), this filter clears the `Authentication` in the `SecurityContextHolder`.

### `ShopifyOAuth2AuthorizationRequestResolver`
- Replaces the default: `DefaultOAuth2AuthorizationRequestResolver`
- Invoked by `OAuth2AuthorizationRequestRedirectFilter`.
- By default, this class will match any request that matches `/install/shopify` and is not authenticated (`OAuth2AuthenticationToken`).
- Its `resolve(...)` method returns null to override the filter's default redirection behavior, EXCEPT when no shop parameter is provided. An implicit `OAuth2AuthorizationRequest` is returned so the filter could handle the redirect. This should never happen in an embedded app.
- Regardless of whether this resolver is called from an embedded app or not, it requires a "shop" request parameter
- This resolver... 
	1. Looks for a `ClientRegistration` that matches "/install/shopify".
	2. Creates an `OAuth2AuthorizationRequest`:
		- clientId: from `ClientRegistration`
		- authorizationUri: uses the "shop" parameter in the request to populate the uri template variable in the authorizationUri stored in the `ProviderDetails` in the `ClientRegistration` (default: "https://{shop}/admin/oauth/authorize")
		- redirectUri: expands and populates the uri template in ClientRegistrarion (default: "{baseUrl}/login/app/oauth2/code/shopify")
		- scopes: from `ClientRegistration`
		- state: generated by `Base64StringKeyGenerator`
		- additionalParameters: contains the registrationId (e.g. "shopify"), and the shop name
	3. Uses the custom `ShopifyHttpSessionOAuth2AuthorizationRequestRepository` to save the `OAuth2AuthorizationRequest` in the HttpSession
	4. Invokes the `ShopifyRedirectStrategy` to set 2 request attributes that contain the 2 authorizationUris that the Shopify-provided Javascript needs to redirect: one for redirecting from the parent and another for redirecting from an iFrame.



The `OAuth2LoginAuthenticationFilter`/`AbstractAuthenticationProcessingFilter` matches the default "{baseUrl}/login/app/oauth2/code/shopify" and...
1. Retrieves and removes the `OAuth2AuthorizationRequest` saved by `ShopifyHttpSessionOAuth2AuthorizationRequestRepository`
2. Builds an `OAuth2AuthorizationResponse` from the Shopify response parameters
3. Builds an `OAuth2AuthorizationExchange` that contains the `OAuth2AuthorizationRequest` and `OAuth2AuthorizationResponse` 
4. Uses the `OAuth2AuthorizationExchange` along with the corresponding Shopify `ClientRegistration` to build an `OAuth2LoginAuthenticationToken`
5. Delegates to `OAuth2LoginAuthenticationProvider`, which returns a `OAuth2LoginAuthenticationToken`
6. Uses the `OAuth2LoginAuthenticationToken` to create an `OAuth2AuthenticationToken` and an `OAuth2AuthorizedClient`
7. Uses the default `AuthenticatedPrincipalOAuth2AuthorizedClientRepository` (which uses the custom `ShopifyOAuth2AuthorizedClientService`) to save the `OAuth2AuthorizedClient`
8. Calls `sessionStrategy.onAuthentication(...)` on the default `NullAuthenticatedSessionStrategy` (does nothing)
9. Calls `successfulAuthentication(...)` which sets the authentication in the `SecurityContextHolder`, takes care of other services, and finally delegates to the custom `NoRedirectSuccessHandler` successHandler



The default `OAuth2LoginAuthenticationProvider`...
1. Uses a custom `OAuth2AccessTokenResponseClient`: `ShopifyAuthorizationCodeTokenResponseClient` to get an `OAuth2AccessTokenResponse`
2. Asks the custom implementation of `OAuth2UserService<OAuth2UserRequest, OAuth2User>`, `DefaultShopifyUserService`, to load the `OAuth2User`.
3. Returns a `OAuth2LoginAuthenticationToken` using the `ClientRegistration`, `AuthorizationExchange`, `OAuth2User`, ...



### `ShopifyAuthorizationCodeTokenResponseClient`
- Replaces the default: `DefaultAuthorizationCodeTokenResponseClient`.
- Invoked by the default `OAuth2LoginAuthenticationProvider`
- Delegates to the default, but first replaces the `OAuth2AccessTokenResponseHttpMessageConverter` with `CustomOAuth2AccessTokenResponseHttpMessageConverter`
- It EXPECTS the shop name to be saved as an additional parameter in the `OAuth2AuthorizationRequest`
- Rewrites every `ClientRegistration`'s tokenUri before delegating to the default, since in Shopify, each tokenUri is unique to the store.
- Before returning the response, it adds the shop name as an additional parameter to the `OAuth2AccessTokenResponse`


### `CustomShopifyOAuth2AccessTokenResponseHttpMessageConverter`
- Replaces the default: `OAuth2AccessTokenResponseHttpMessageConverter`
- Invoked by `DefaultAuthorizationCodeTokenResponseClient`
- Still uses the default in `OAuth2AccessTokenResponseHttpMessageConverter` to write the request. Only the converter used to read the response is replaced.
- The default converter expects a "token_type" parameter in the response along with the token, but Shopify does not send it. Also, Shopify sends the scope as a string delimited by "," instead of the default " ". This converter takes care of these issues.



### `ShopifyHttpSessionOAuth2AuthorizationRequestRepository`*
- "Replaces" the default: `HttpSessionOAuth2AuthorizationRequestRepository`
- Invoked by:
	1. `ShopifyOAuth2AuthorizationRequestResolver`: to save the `OAuth2AuthorizationRequest`
	2. `ShopifyVerificationStrategy`: to extract the current `OAuth2AuthorizationRequest`
	3. `BehindHttpsProxyFilter`: to extract the current `OAuth2AuthorizationRequest`
- In the `ShopifyOAuth2AuthorizationRequestResolver`, when we call the requestRepository's `saveAuthorizationRequest()` method, we don't have an `HttpServletResponse`. `ShopifyHttpSessionOAuth2AuthorizationRequestRepository` is functionally identical but with a different method signature. The `OAuth2AuthorizationRequest` is saved in the session as a `Map<String, OAuth2AuthorizationRequest>`


### `ShopifyRedirectStrategy`*
- "Replaces" the default:` DefaultRedirectStrategy`
- Invoked by `ShopifyOAuth2AuthorizationRequestResolver`
- Instead of redirecting, it saves 2 authorization redirection URIs as request attributes. This allows for "redirecting" from an iFrame in an embedded app setting.
- This means that a request to "/install/**" will have either:
	1. `OAuth2AuthenticationToken`: if the request came from an embedded app that has already installed this app
	2. `AnonymousAuthenticationToken`: if the request is not coming from an embedded app (regardless of whether or not this app has been installeds)
	3. `ShopifyOriginToken`: if the request came from an embedded app (and this app has not been installed)


* Note: The classes they replace would be invoked in the `OAuth2LoginAuthenticationFilter`, but since they are not (since the resolver returns null), we are forced to use their functional equivalents in the resolver.



### `DefaultShopifyUserService`
- Replaces the `DefaultOAuth2UserService`
- Invoked by `OAuth2LoginAuthenticationProvider`
- Instead of making a request for user info, this implementation instantiates a `ShopifyStore` that contains:
	1. the name of the store as the principal name
	2. the access token as an additional attribute
	3. the api key as an additional attribute
- This `ShopifyStore` is returned to the provider
- The shop name is retrieved from the `OAuth2UserRequest` that was passed in. The `ShopifyAuthorizationCodeTokenResponseClient` sets it as an additional parameter in the `OAuth2AccessTokenResponse`, whose additional parameters are used to create a `OAuth2UserRequest`


### `NoRedirectSuccessHandler`
- Invoked by `OAuth2LoginAuthenticationFilter` after successful authentication
- Replaces/decorates the default: `SavedRequestAwareAuthenticationSuccessHandler`
- Since we can't redirect in an embedded app, an "empty" redirect strategy is given to `SavedRequestAwareAuthenticationSuccessHandler`
- This handler delegates to `SavedRequestAwareAuthenticationSuccessHandler` for cleanup, and to take care of everything, except for redirecting.
- It performs a forward to the "authorization url", which bypasses the filter chain.


### `ShopifyOAuth2AuthorizedClientService`
- Replaces the default: `InMemoryOAuth2AuthorizedClientService` (as stipulated by `OAuth2ClientConfigurerUtils`)
- Invoked by `OAuth2LoginAuthenticationFilter` when it invokes the default `AuthenticatedPrincipalOAuth2AuthorizedClientRepository` to save the `OAuth2AuthorizedClient` after a user has authenticated
- Instead of saving them in memory, this implementation attempts to use the custom tokenService to save the store in a database, or to update the store credentials if this store has already been "installed". 
- When building the `OAuth2LoginFilter`, `OAuth2ClientConfigurerUtils` finds this bean.
- It is also invoked by `ShopifyExistingFilter` to see if, in an embedded app, the shop has already installed this app.

**NOTE: updating store credentials will only happen when `ShopifyOAuth2AuthorizedClientService` is called. In an embedded app, it is only called once: when installing. Afterwards, log in directly from the browser to call it.**

### `ShopifyVerificationStrategy`
- Invoked by `ShopifyOriginFilter` and `UninstallFilter`
- Uses `ClientRegistrationRepository` and `ShopifyHttpSessionOAuth2AuthorizationRequestRepository`
- A request came from Shopify if it has a valid HMAC parameter
- But for the "whitelisted redirection url", it is also necessary that it provide a nonce in the "state" parameter. Since this is a redirection url, the `OAuth2AuthorizationRequest` should have already been saved in the `HttpSession`. See `ShopifyHttpSessionOAuth2AuthorizationRequestRepository`
- This class also provides the logic to verify that an uninstall request came from Shopify by inspecting certain request headers. 

### `BehindHttpsProxyFilter`
- Invoked before the `OAuth2LoginAuthenticationFilter`
- A problem occurs if this application is running behind a reverse proxy, because Shopify requires SSL connections, and although the reverse proxy might connect to Shopify via SSL, the `HttpServletRequest` object will still have "http" as its scheme. This is problematic, because although the `ShopifyOAuth2AuthorizationRequestResolver` is hard coded to create a redirect uri with an https scheme (which is stored in `OAuth2AuthorizationRequest`), the default `OAuth2LoginAuthenticationProvider` uses the `OAuth2AuthorizationExchangeValidator` to compare the current url (http) to the redirect uri (https). 
- This filter wraps the redirectionPath (/login/app/oauth2/code/...) and loginPath (/install/...) in a `HttpServletRequestWrapper` that overrides the scheme to "https" and server port to 443


## Uninstalling
### `UninstallFilter`
- Invoked when the request matches the default uninstallation uri: /store/uninstall/shopify
- Delegates to `ShopifyVerificationStrategy` to make sure the request came from Shopify before removing the store and all associated information from the database
