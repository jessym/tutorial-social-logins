package com.jessym.tutorial.security;

import com.jessym.tutorial.controllers.OAuthController;
import com.jessym.tutorial.security.oauth.CustomAuthorizationRedirectFilter;
import com.jessym.tutorial.security.oauth.CustomAuthorizationRequestResolver;
import com.jessym.tutorial.security.oauth.CustomAuthorizedClientService;
import com.jessym.tutorial.security.oauth.CustomStatelessAuthorizationRequestRepository;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final OAuthController oauthController;
    private final CustomAuthorizedClientService customAuthorizedClientService;
    private final CustomAuthorizationRedirectFilter customAuthorizationRedirectFilter;
    private final CustomAuthorizationRequestResolver customAuthorizationRequestResolver;
    private final CustomStatelessAuthorizationRequestRepository customStatelessAuthorizationRequestRepository;

    @Override
    @SneakyThrows
    protected void configure(HttpSecurity httpSecurity) {
        httpSecurity
                // Endpoint protection
                .authorizeHttpRequests(config -> {
                    config.anyRequest().permitAll();
                })
                // Disable "JSESSIONID" cookies
                .sessionManagement(config -> {
                    config.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })
                // OAuth2 (social logins)
                .oauth2Login(config -> {
                    config.authorizationEndpoint(subconfig -> {
                        subconfig.baseUri(OAuthController.AUTHORIZATION_BASE_URL);
                        subconfig.authorizationRequestResolver(this.customAuthorizationRequestResolver);
                        subconfig.authorizationRequestRepository(this.customStatelessAuthorizationRequestRepository);
                    });
                    config.redirectionEndpoint(subconfig -> {
                        subconfig.baseUri(OAuthController.CALLBACK_BASE_URL + "/*");
                    });
                    config.authorizedClientService(this.customAuthorizedClientService);
                    config.successHandler(this.oauthController::oauthSuccessResponse);
                    config.failureHandler(this.oauthController::oauthFailureResponse);
                })
                // Filters
                .addFilterBefore(this.customAuthorizationRedirectFilter, OAuth2AuthorizationRequestRedirectFilter.class)
                // Auth exceptions
                .exceptionHandling(config -> {
                    config.accessDeniedHandler(this::accessDenied);
                    config.authenticationEntryPoint(this::accessDenied);
                });
    }

    @SneakyThrows
    private void accessDenied(HttpServletRequest request, HttpServletResponse response, Exception authException) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{ \"error\": \"Access Denied\" }");
    }

}
