package com.bankinghub.backend.config;

import com.bankinghub.backend.security.UserPrincipal;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

/**
 * JPA Auditing configuration for automatic audit trail tracking.
 * <p>
 * Enables JPA auditing and provides an auditor provider that extracts
 * the current user's email from the security context for audit fields.
 * </p>
 * 
 * @author Melvin Musonda Chibanda
 * @version 2.0.0
 * @since 2.0.0
 */
@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorProvider")
public class JpaAuditingConfig {

    /**
     * Provides the current auditor (user) for JPA auditing.
     * <p>
     * Extracts the authenticated user's email from the security context.
     * Returns "system" for unauthenticated requests.
     * </p>
     * 
     * @return AuditorAware instance that provides current user's email
     */
    @Bean
    public AuditorAware<String> auditorProvider() {
        return () -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated() || 
                authentication.getPrincipal().equals("anonymousUser")) {
                return Optional.of("system");
            }
            
            if (authentication.getPrincipal() instanceof UserPrincipal userPrincipal) {
                return Optional.of(userPrincipal.getEmail());
            }
            
            return Optional.of(authentication.getName());
        };
    }
}
