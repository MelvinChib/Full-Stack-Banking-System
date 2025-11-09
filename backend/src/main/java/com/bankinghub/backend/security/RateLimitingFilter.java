package com.bankinghub.backend.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Rate limiting filter to prevent brute force attacks and API abuse.
 * <p>
 * Implements sliding window rate limiting with separate limits for:
 * - General API requests: 20 requests per minute per IP
 * - Login attempts: 5 attempts per minute per IP
 * </p>
 * 
 * @author Melvin Musonda Chibanda
 * @version 2.0.0
 * @since 2.0.0
 */
@Slf4j
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    /** Maximum general requests allowed per minute per IP */
    private static final int MAX_REQUESTS_PER_MINUTE = 20;
    
    /** Maximum login attempts allowed per minute per IP */
    private static final int MAX_LOGIN_ATTEMPTS = 5;
    
    /** Time window size in milliseconds (1 minute) */
    private static final long WINDOW_SIZE_MS = 60_000;
    
    /** Tracks general request counts per IP address */
    private final Map<String, RequestWindow> requestCounts = new ConcurrentHashMap<>();
    
    /** Tracks login attempt counts per IP address */
    private final Map<String, RequestWindow> loginAttempts = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        String clientIp = getClientIp(request);
        String requestUri = request.getRequestURI();
        
        // Rate limit login attempts
        if (requestUri.contains("/auth/login")) {
            if (isLoginRateLimited(clientIp)) {
                log.warn("Login rate limit exceeded for IP: {}", clientIp);
                response.setStatus(429); // Too Many Requests
                response.getWriter().write("{\"error\":\"Too many login attempts. Please try again later.\"}");
                return;
            }
        }
        
        // General rate limiting
        if (isRateLimited(clientIp)) {
            log.warn("Rate limit exceeded for IP: {}", clientIp);
            response.setStatus(429); // Too Many Requests
            response.getWriter().write("{\"error\":\"Too many requests. Please try again later.\"}");
            return;
        }
        
        filterChain.doFilter(request, response);
    }

    /**
     * Checks if general rate limit is exceeded for the given IP.
     * 
     * @param clientIp Client IP address
     * @return true if rate limit exceeded, false otherwise
     */
    private boolean isRateLimited(String clientIp) {
        RequestWindow window = requestCounts.computeIfAbsent(clientIp, k -> new RequestWindow());
        return !window.allowRequest(MAX_REQUESTS_PER_MINUTE);
    }

    /**
     * Checks if login rate limit is exceeded for the given IP.
     * 
     * @param clientIp Client IP address
     * @return true if login rate limit exceeded, false otherwise
     */
    private boolean isLoginRateLimited(String clientIp) {
        RequestWindow window = loginAttempts.computeIfAbsent(clientIp, k -> new RequestWindow());
        return !window.allowRequest(MAX_LOGIN_ATTEMPTS);
    }

    /**
     * Extracts client IP address from request headers or remote address.
     * Checks X-Forwarded-For and X-Real-IP headers for proxy scenarios.
     * 
     * @param request HTTP request
     * @return Client IP address
     */
    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }

    /**
     * Sliding window for tracking request counts within a time period.
     * Thread-safe implementation using atomic operations.
     */
    private static class RequestWindow {
        /** Atomic counter for requests in current window */
        private final AtomicInteger count = new AtomicInteger(0);
        
        /** Start time of current window in milliseconds */
        private volatile long windowStart = System.currentTimeMillis();

        /**
         * Checks if a request is allowed within the rate limit.
         * Resets the window if time period has elapsed.
         * 
         * @param maxRequests Maximum allowed requests in window
         * @return true if request is allowed, false if limit exceeded
         */
        synchronized boolean allowRequest(int maxRequests) {
            long now = System.currentTimeMillis();
            
            if (now - windowStart > WINDOW_SIZE_MS) {
                windowStart = now;
                count.set(0);
            }
            
            return count.incrementAndGet() <= maxRequests;
        }
    }
}
