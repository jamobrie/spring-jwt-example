package io.jsonwebtoken.jjwtfun.config;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.jjwtfun.service.SecretService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    CsrfTokenRepository jwtCsrfTokenRepository;

    @Autowired
    SecretService secretService;

    // ordered so we can use binary search below
    private final String[] ignoreCsrfAntMatchers =
            {
                    "/dynamic-builder-compress",
                    "/dynamic-builder-general",
                    "/dynamic-builder-specific",
                    "/set-secrets"
            };


    // TODO -> Investigate builder pattern here in particular
    // TODO ---> Learn the following:
    // First, we are saying the CSRF tokens are not required when posting to our REST API endpoints (line 15).
    // Second, we are saying that unauthenticated access should be allowed for all endpoints
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterAfter(new JwtCsrfValidatorFilter(), CsrfFilter.class)
                .csrf()
                .csrfTokenRepository(jwtCsrfTokenRepository)
                .ignoringAntMatchers(ignoreCsrfAntMatchers)
                .and()
                .authorizeRequests()
                .antMatchers("/**")
                .permitAll();
    }


    //Thymeleaf template ---> will POST to the same endpoint when submitted. Notice that there is no explicit reference to CSRF tokens in the form.
    //jwt-csrf-form.html is file being reference -> Notice without the file the difference in the browser! //TODO try that
    //hymeleaf templates are automatically inserting the CSRF token.
    //... it's private as it's an inner class of our Spring Security configuration
    private class JwtCsrfValidatorFilter extends OncePerRequestFilter {
//TODO Understand the filter here!
        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
            // NOTE: A real implementation should have a nonce cache so the token cannot be reused

            CsrfToken token = (CsrfToken) request.getAttribute("_csrf");

            if (
                // only care if it's a POST ---> //TODO Verify with GET in Postman
                    "POST".equals(request.getMethod()) &&
                            // ignore if the request path is in our list
                            Arrays.binarySearch(ignoreCsrfAntMatchers, request.getServletPath()) < 0 &&
                            // make sure we have a token
                            token != null) {
                // CsrfFilter already made sure the token matched. Here, we'll make sure it's not expired
                try {
                    Jwts.parser()
                            .setSigningKeyResolver(secretService.getSigningKeyResolver())
                            .parseClaimsJws(token.getToken());
                } catch (JwtException e) {
                    // most likely an ExpiredJwtException, but this will handle any
                    request.setAttribute("exception", e);
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    RequestDispatcher dispatcher = request.getRequestDispatcher("expired-jwt");
                    dispatcher.forward(request, response);
                }
            }

            filterChain.doFilter(request, response);
        }
    }
}
