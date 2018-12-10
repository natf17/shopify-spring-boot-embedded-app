How it works


***************************************
The installation endpoint (first time):
(default: /install)

ShopifyOriginFilter
- For every request, sets a ShopifyOriginToken as the Authentication object if it is determined that the request came from shopify

ShopifyExistingTokenFilter
- matches installation endpoint path (/install)
- if there is a ShopifyOriginToken as the Authentication, attempt to replace it with a OAuth2PersistedAuthenticationToken retrived from the TokenService... will do so only if this store has already been installed

// expects: shop parameter in request
OAuth2AuthorizationRequestRedirectFilter
- calls the custom ShopifyOauth2AuthorizationRequestResolver.resolve(HttpServletRequest)
- will return null if already authenticated via OAuth2PersistedAuthenticationToken
- if there's a match between the request and the authorizationRequestBaseUri provided via its constructor, 
- gets a ClientRegistration that matches authorizationRequestBaseUri/{registrationId} (default: /install/shopify)
- create an OAuth2AuthorizationRequest:
	- clientId: from ClientRegistration
	- authorizationUri: uses the "shop" parameter in the request to populate the uri template variable in the authorizationUri stored in the ProviderDetails in the ClientRegistration (default: "https://{shop}/admin/oauth/authorize")
	- redirectUri: expands and populates the uri template in ClientRegistrarion (default: "{baseUrl}/login/app/oauth2/code/{registrationId}")
	- scopes: from ClientRegistration
	- state: generated by Base64StringKeyGenerator
	- additionalParameters: contains the registrationId, and the shop name

- ShopifyHttpSessionOAuth2AuthorizationRequestRepository saves the OAuth2AuthorizationRequest in HttpSession
- ShopifyRedirectStrategy sets an AuthenticationRedirectUriHolder in the Authentication. This temporary object contains the 2 authorizationUris that the Shopify-provided Javascript script needs to redirect: one for redirecting from the parent and another for redirecting from an iFrame.

// The javascript forces a redirect to one of the authorizationUris in AuthenticationRedirectUriHolder
// Once the user grants access, Shopify will redirect to the redirectUri, default: "/login/app/oauth2/code/shopify"


OAuth2LoginAuthenticationFilter
- matches on the redirectUri
- when attempting to authenticate, first retrieves and removes the OAuth2AuthorizationRequest saved by ShopifyHttpSessionOAuth2AuthorizationRequestRepository
- Builds an OAuth2AuthorizationResponse from the Shopify response parameters
- Builds an OAuth2AuthorizationExchange that contains the OAuth2AuthorizationRequest and OAuth2AuthorizationResponse and uses the OAuth2AuthorizationExchange along with the corresponding Shopify ClientRegistration to build an OAuth2LoginAuthenticationToken
- Pass it to OAuth2LoginAuthenticationProvider

OAuth2LoginAuthenticationProvider
- Uses a OAuth2AccessTokenResponseClient: ShopifyAuthorizationCodeTokenResponseClient
ShopifyAuthorizationCodeTokenResponseClient vs default(DefaultAuthorizationCodeTokenResponseClient)
1. ShopifyAuthorizationCodeTokenResponseClient modifies the ClientRegistration by rewriting the tokenUri, since in Shopify, each tokenUri is unique to the store
2. Builds an DefaultAuthorizationCodeTokenResponseClient but swaps the default OAuth2AccessTokenResponseHttpMessageConverter for CustomShopifyOAuth2AccessTokenResponseHttpMessageConverter. This is because the default converter expects a "token_type" parameter in the response along with the token, but Shopify does not send it. Also, Shopify sends the scope as a string delimited by ", " instead of the default " ".

OAuth2LoginAuthenticationProvider
- OAuth2AccessTokenResponse
// asks the OAuth2UserService<OAuth2UserRequest, OAuth2User> userService) to load the user... DO NOTHING
 returns a OAuth2LoginAuthenticationToken to the Filter


...OAuth2LoginAuthenticationFilter
- use OAuth2LoginAuthenticationToken to create a OAuth2AuthenticationToken and a OAuth2AuthorizedClient
- use authorizedClientRepository(default AuthenticatedPrincipalOAuth2AuthorizedClientRepository uses the custom ShopifyOAuth2AuthorizedClientService) to save the OAuth2AuthorizedClient
- return the OAuth2AuthenticationToken


AbstractAuthenticationProcessingFilter doFilter()
- calls sessionStrategy.onAuthentication(...,...,...) NullAuthenticatedSessionStrategy
- calls successfulAuthentication(...) which sets the authentication in the SecurityContextHolder
- FINALLY delegates successHandler.onAuthenticationSuccess(request, response, authResult); (default: SavedRequestAwareAuthenticationSuccessHandler) -> should end up at /install. replaced by custom NoRedirectSuccessHandler

// NO REDIRECT UPON 




ShopifyHttpSessionOAuth2AuthorizationRequestRepository vs the default(HttpSessionOAuth2AuthorizationRequestRepository)
- In the ShopifyOauth2AuthorizationRequestResolver, when we call the requestRepository's saveAuthorizationRequest() method, we don't have an HttpServletResponse. ShopifyHttpSessionOAuth2AuthorizationRequestRepository does the same but with a different method signature

***********************************

TODO

1. an authentication entry point provided to exceptionHandling() (which then gives it to oauth2login())
should simply print an error (redirects not supported in iframe)







Every other request