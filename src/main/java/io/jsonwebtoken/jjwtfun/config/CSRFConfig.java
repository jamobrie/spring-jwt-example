package io.jsonwebtoken.jjwtfun.config;

import io.jsonwebtoken.jjwtfun.service.SecretService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.csrf.CsrfTokenRepository;

@Configuration
public class CSRFConfig {

    @Autowired
    SecretService secretService;

    @Bean //TODO Try to do this without the need of the bean annotation
    @ConditionalOnMissingBean //TODO investigate this annotation!
    public CsrfTokenRepository jwtCsrfTokenRepository() {
        return new JWTCsrfTokenRepository(secretService.getHS256SecretBytes());
    }
}
