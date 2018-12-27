# The How

Note: This Spring Security application requires the Java Cryptography Encryption policy files for encryption.

See https://www.oracle.com/technetwork/java/javase/downloads/jce-all-download-5170447.html

***************************************

### `ShopifyOriginFilter`
- This filter makes sure the request possesses the necessary information to verify the request came from Shopify.
- If the request is to the application installation path, this filter sets a `ShopifyOriginToken` as the `Authentication` object if it is determined that the request came from Shopify (and if there is no "Shopify" Authentication object already).
- If the request is to what Shopify calls the "whitelisted redirection url", and if the request did not come from Shopify, a 403 response is sent via the AccessDeniedHandler.
- See ShopifyVerificationStrategy for how it is determined if a request came from Shopify

### `ShopifyExistingTokenFilter`
- This filter matches the installation endpoint path (/install)
- If there is a `ShopifyOriginToken` as the `Authentication`, attempt to replace it with a `OAuth2AuthenticationToken` using the `OAuth2AuthorizedClient` retrived from the `TokenService`. This will be successful only if this store has already been installed. As a side note, the only way this path can be reached with an `ShopifyOriginToken` is in the embedded app scenario, where Shopify itself invokes the installation uri.
- If none exists (the store has not been installed as an embedded app or this call is comming as a regular request), this filter will not modify the `Authentication` in the `SecurityContextHolder`.
- For every request, clears the `SecurityContextHolder` of `AuthenticationRedirectUriHolder`.

### `ShopifyOAuth2AuthorizationRequestResolver`
- Replaces the default: `DefaultOAuth2AuthorizationRequestResolver`
- Invoked by `OAuth2AuthorizationRequestRedirectFilter`.
- By default, this class will match any request that matches `/install/shopify`.
- Its `resolve(...)` method always returns null to override the filter's default redirection behavior.
- If the user is authenticated (via `OAuth2AuthenticationToken`) or if the shop parameter is not provided (if this is not from the embedded app, we at least need the shop name to initiate the OAuth flow with Shopify), then this class does nothing else.
- If not, this resolver... 
	1. Looks for a `ClientRegistration` that matches "/install/shopify".
	2. Creates an `OAuth2AuthorizationRequest`:
		- clientId: from `ClientRegistration`
		- authorizationUri: uses the "shop" parameter in the request to populate the uri template variable in the authorizationUri stored in the `ProviderDetails` in the `ClientRegistration` (default: "https://{shop}/admin/oauth/authorize")
		- redirectUri: expands and populates the uri template in ClientRegistrarion (default: "{baseUrl}/login/app/oauth2/code/shopify")
		- scopes: from `ClientRegistration`
		- state: generated by `Base64StringKeyGenerator`
		- additionalParameters: contains the registrationId, and the shop name
	3. Uses the custom `ShopifyHttpSessionOAuth2AuthorizationRequestRepository` to save the `OAuth2AuthorizationRequest` in the HttpSession
	4. Invokes the `ShopifyRedirectStrategy` to set an `AuthenticationRedirectUriHolder` in the `Authentication`. This temporary object contains the 2 authorizationUris that the Shopify-provided Javascript needs to redirect: one for redirecting from the parent and another for redirecting from an iFrame.



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
1. Uses a custom `OAuth2AccessTokenResponseClient`: `ShopifyAuthorizationCodeTokenResponseClient` to get a `OAuth2AccessTokenResponse`
2. Asks the custom implementation of `OAuth2UserService<OAuth2UserRequest, OAuth2User>` userService), `DefaultShopifyUserService`, to load the `OAuth2User`.
3. Returns a `OAuth2LoginAuthenticationToken` using the `ClientRegistration`, `AuthorizationExchange`, `OAuth2User`, ...



### `ShopifyAuthorizationCodeTokenResponseClient`
- Replaces the default: `DefaultAuthorizationCodeTokenResponseClient`.
- Invoked by the default `OAuth2LoginAuthenticationProvider`
- Delegates to the default, but first replaces the `OAuth2AccessTokenResponseHttpMessageConverter` with `CustomOAuth2AccessTokenResponseHttpMessageConverter`
- Rewrites every `ClientRegistration`'s tokenUri before delegating to the default, since in Shopify, each tokenUri is unique to the store.
- Before returning the response, it adds the shop name as an additional parameter to the `OAuth2AccessTokenResponse`


### `CustomShopifyOAuth2AccessTokenResponseHttpMessageConverter`
- Replaces the default: `OAuth2AccessTokenResponseHttpMessageConverter`
- Invoked by `DefaultAuthorizationCodeTokenResponseClient`
- The default converter expects a "token_type" parameter in the response along with the token, but Shopify does not send it. Also, Shopify sends the scope as a string delimited by "," instead of the default " ". This converter takes care of these issues.



### `ShopifyHttpSessionOAuth2AuthorizationRequestRepository`*
- "Replaces" the default: `HttpSessionOAuth2AuthorizationRequestRepository`
- Invoked by `ShopifyOAuth2AuthorizationRequestResolver`, 'ShopifyVerificationStrategy', and 'BehindHttpsProxyFilter'
- In the `ShopifyOAuth2AuthorizationRequestResolver`, when we call the requestRepository's `saveAuthorizationRequest()` method, we don't have an `HttpServletResponse`. `ShopifyHttpSessionOAuth2AuthorizationRequestRepository` is functionally identical but with a different method signature.
- In 'ShopifyVerificationStrategy' and 'BehindHttpsProxyFilter', we need to extract the current `OAuth2AuthorizationRequest` for the request. This class provides that functionality.


### `ShopifyRedirectStrategy`*
- "Replaces" the default:` DefaultRedirectStrategy`
- Invoked by `ShopifyOAuth2AuthorizationRequestResolver`
- It does not redirect
- It populates `Authentication` with a `AuthenticationRedirectUriHolder`, which contains the redirection URIs the Javascript will use to redirect. This allows for "redirecting" from an iFrame in an embedded app setting.


* Note: The classes they replace would be invoked in the `OAuth2LoginAuthenticationFilter`, but since they are not (since the resolver always returns null), we are forced to use their functional equivalents in the resolver.



### `DefaultShopifyUserService`
- Replaces the `DefaultOAuth2UserService`
- Invoked by `OAuth2LoginAuthenticationProvider`
- Instead of making a request for UserInfo, this implementation instantiates a `ShopifyStore` that contains the name of the store, and its access token, and returns it to the provider
- The shop name is retrieved from the `OAuth2UserRequest` that was passed in. The `ShopifyAuthorizationCodeTokenResponseClient` sets it as an additional parameter in the `OAuth2AccessTokenResponse`, whose additional parameters are used to create a `OAuth2UserRequest`


### `NoRedirectSuccessHandler`
- Replaces/decorates the default: `SavedRequestAwareAuthenticationSuccessHandler`
- Since we can't redirect in an embedded app, an "empty" redirect strategy is given to `SavedRequestAwareAuthenticationSuccessHandler`
- This handler delegates to `SavedRequestAwareAuthenticationSuccessHandler` for cleanup, and to take care of everything, except for redirecting.
- It performs a forward to the "authorization url".


### `ShopifyOAuth2AuthorizedClientService`
- Replaces the default: `InMemoryOAuth2AuthorizedClientService` (as stipulated by `OAuth2ClientConfigurerUtils`)
- Invoked by `OAuth2LoginAuthenticationFilter` when it invokes the default `AuthenticatedPrincipalOAuth2AuthorizedClientRepository` after a user has authenticated
- Instead of saving them in memory, this implementation attempts to use the custom tokenService to save the store in a database, or to update the store credentials if this store has already been "installed".

### 'ShopifyVerificationStrategy'
- Invoked by `ShopifyOriginFilter`
- A request came from Shopify if it has a valid HMAC parameter
- But for the "whitelisted redirection url", it is also necessary that it provide a nonce in the "state" parameter. Since this is a redirection url, the `OAuth2AuthorizationRequest` should have already been saved in the HttpSession. See `ShopifyHttpSessionOAuth2AuthorizationRequestRepository`

### 'BehindHttpsProxyFilter'
- Invoked before the OAuth2LoginAuthenticationFilter
- A problem occurs if this application is running behind a reverse proxy, because Shopify requires SSL connections, and although the reverse proxy might connect to Shopify via SSL, the HttpServletRequest object will still have "http" as its scheme. This is problematic, because although the ShopifyOAuth2AuthorizationRequestResolver is hard coded to create a redirect uri with an https scheme (which is stored in OAuth2AuthorizationRequest), the default OAuth2LoginAuthenticationProvider uses the OAuth2AuthorizationExchangeValidator to compare the current url (http) to the redirect uri (https). 
- This filter wraps the redirectionPath (/login/app/oauth2/code/...) and loginPath (/install/...) in a HttpServletRequestWrapper that overrides the scheme to "https" and server port to 443

Todo:
- tests!
