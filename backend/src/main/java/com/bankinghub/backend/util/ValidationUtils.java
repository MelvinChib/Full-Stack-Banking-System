package com.bankinghub.backend.util;

import com.bankinghub.backend.config.SecurityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.util.regex.Pattern;

/**
 * Utility class for input validation and sanitization.
 * <p>
 * Provides comprehensive validation methods for:
 * - Email addresses
 * - Passwords (configurable strength requirements)
 * - Phone numbers (international and Zambian formats)
 * - Account numbers and routing numbers
 * - Monetary amounts and percentages
 * - SQL injection and XSS attack detection
 * - Input sanitization
 * </p>
 * 
 * @author Melvin Musonda Chibanda
 * @version 2.0.0
 * @since 1.0.0
 */
@Component
@RequiredArgsConstructor
public class ValidationUtils {

    private final SecurityProperties securityProperties;

    /** Patterns for detecting SQL injection attempts */
    private static final Pattern[] SQL_INJECTION_PATTERNS = {
        Pattern.compile("(?i).*(union|select|insert|update|delete|drop|create|alter|exec|execute).*"),
        Pattern.compile("(?i).*(script|javascript|vbscript|onload|onerror).*"),
        Pattern.compile(".*[';\"\\\\].*")
    };

    /** Patterns for detecting XSS (Cross-Site Scripting) attempts */
    private static final Pattern[] XSS_PATTERNS = {
        Pattern.compile("(?i).*<script.*>.*</script>.*"),
        Pattern.compile("(?i).*javascript:.*"),
        Pattern.compile("(?i).*on\\w+\\s*=.*")
    };

    /** Pattern for validating email addresses */
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$"
    );

    /** Pattern for validating international phone numbers */
    private static final Pattern PHONE_PATTERN = Pattern.compile("^[+]?[1-9]\\d{1,14}$");
    
    /** Pattern for validating account numbers (8-20 alphanumeric characters) */
    private static final Pattern ACCOUNT_NUMBER_PATTERN = Pattern.compile("^[A-Za-z0-9]{8,20}$");
    
    /** Pattern for validating bank routing numbers (9 digits) */
    private static final Pattern ROUTING_NUMBER_PATTERN = Pattern.compile("^\\d{9}$");

    /**
     * Validates email format with security checks.
     * 
     * @param email Email address to validate
     * @return true if valid, false otherwise
     */
    public boolean isValidEmail(String email) {
        return email != null && !containsSqlInjection(email) && !containsXss(email) && EMAIL_PATTERN.matcher(email).matches();
    }

    /**
     * Validates password strength based on configured requirements.
     * 
     * @param password Password to validate
     * @return true if meets strength requirements, false otherwise
     */
    public boolean isValidPassword(String password) {
        if (password == null) return false;
        SecurityProperties.Security.PasswordStrength strength = securityProperties.getSecurity().getPasswordStrength();
        if (password.length() < strength.getMinLength()) return false;
        if (strength.isRequireUppercase() && !password.chars().anyMatch(Character::isUpperCase)) return false;
        if (strength.isRequireLowercase() && !password.chars().anyMatch(Character::isLowerCase)) return false;
        if (strength.isRequireDigit() && !password.chars().anyMatch(Character::isDigit)) return false;
        if (strength.isRequireSpecialChar() && !password.chars().anyMatch(ch -> "!@#$%^&*()_+-=[]{}|;:,.<>?".indexOf(ch) >= 0)) return false;
        return true;
    }

    public boolean isValidPhoneNumber(String phoneNumber) {
        return phoneNumber != null && !containsSqlInjection(phoneNumber) && PHONE_PATTERN.matcher(phoneNumber).matches();
    }

    public boolean isValidAccountNumber(String accountNumber) {
        return accountNumber != null && !containsSqlInjection(accountNumber) && ACCOUNT_NUMBER_PATTERN.matcher(accountNumber).matches();
    }

    public boolean isValidRoutingNumber(String routingNumber) {
        return routingNumber != null && ROUTING_NUMBER_PATTERN.matcher(routingNumber).matches();
    }

    /**
     * Validates monetary amount (positive and within range).
     * 
     * @param amount Amount to validate
     * @return true if valid, false otherwise
     */
    public boolean isValidAmount(BigDecimal amount) {
        return amount != null && amount.compareTo(BigDecimal.ZERO) > 0 && amount.compareTo(new BigDecimal("9999999999999.99")) <= 0;
    }

    /**
     * Validates transfer amount (minimum 1.00 ZMW, maximum 1M ZMW).
     * 
     * @param amount Transfer amount to validate
     * @return true if valid, false otherwise
     */
    public boolean isValidTransferAmount(BigDecimal amount) {
        return amount != null && amount.compareTo(new BigDecimal("1.00")) >= 0 && amount.compareTo(new BigDecimal("1000000.00")) <= 0;
    }

    public boolean isValidPercentage(BigDecimal percentage) {
        return percentage != null && percentage.compareTo(BigDecimal.ZERO) >= 0 && percentage.compareTo(new BigDecimal("100.00")) <= 0;
    }

    public boolean isValidLength(String str, int minLength, int maxLength) {
        if (str == null) return false;
        int length = str.trim().length();
        return length >= minLength && length <= maxLength;
    }

    public boolean isEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }

    public boolean isNotEmpty(String str) {
        return !isEmpty(str);
    }

    /**
     * Validates Zambian phone number format.
     * Supports formats: +260977123456, 0977123456, 260977123456
     * 
     * @param phoneNumber Phone number to validate
     * @return true if valid Zambian number, false otherwise
     */
    public boolean isValidZambianPhoneNumber(String phoneNumber) {
        if (phoneNumber == null) return false;
        String cleanNumber = phoneNumber.replaceAll("[\\s\\-\\(\\)]", "");
        Pattern zambianMobilePattern = Pattern.compile("^(\\+260|260|0)?(9[567]\\d{7}|7[67]\\d{7})$");
        return zambianMobilePattern.matcher(cleanNumber).matches();
    }

    public boolean isValidZambianNRC(String nrc) {
        if (nrc == null) return false;
        String cleanNRC = nrc.replaceAll("[\\s/]", "");
        Pattern nrcPattern = Pattern.compile("^\\d{6}\\d{2}\\d{1}$");
        return nrcPattern.matcher(cleanNRC).matches();
    }

    public String sanitizeString(String input) {
        if (input == null) return null;
        return input.replaceAll("[<>\"'%;()&+]", "").trim();
    }

    public boolean isValidName(String name) {
        if (name == null) return false;
        Pattern namePattern = Pattern.compile("^[a-zA-Z\\s\\-']{2,50}$");
        return namePattern.matcher(name.trim()).matches();
    }

    public boolean areEqual(String str1, String str2) {
        if (str1 == null && str2 == null) return true;
        if (str1 == null || str2 == null) return false;
        return str1.equals(str2);
    }

    /**
     * Checks if input contains SQL injection patterns.
     * 
     * @param input String to check
     * @return true if SQL injection detected, false otherwise
     */
    public boolean containsSqlInjection(String input) {
        if (input == null) return false;
        String cleanInput = input.toLowerCase().trim();
        for (Pattern pattern : SQL_INJECTION_PATTERNS) {
            if (pattern.matcher(cleanInput).matches()) return true;
        }
        return false;
    }

    /**
     * Checks if input contains XSS (Cross-Site Scripting) patterns.
     * 
     * @param input String to check
     * @return true if XSS detected, false otherwise
     */
    public boolean containsXss(String input) {
        if (input == null) return false;
        for (Pattern pattern : XSS_PATTERNS) {
            if (pattern.matcher(input).matches()) return true;
        }
        return false;
    }

    /**
     * Sanitizes input by removing dangerous characters and normalizing whitespace.
     * 
     * @param input String to sanitize
     * @return Sanitized string or null if input is null
     */
    public String sanitizeInput(String input) {
        if (input == null) return null;
        return input.trim().replaceAll("[<>\"'&]", "").replaceAll("\\s+", " ");
    }

    /**
     * Evaluates and returns password strength description.
     * 
     * @param password Password to evaluate
     * @return Strength description: Very Strong, Strong, Medium, Weak, Very Weak
     */
    public String getPasswordStrengthDescription(String password) {
        if (password == null || password.length() < 8) return "Too short (minimum 8 characters)";
        boolean hasUpper = password.matches(".*[A-Z].*");
        boolean hasLower = password.matches(".*[a-z].*");
        boolean hasDigit = password.matches(".*\\d.*");
        boolean hasSpecial = password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{}|;:,.<>?].*");
        int strength = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSpecial ? 1 : 0) + (password.length() >= 12 ? 1 : 0);
        return switch (strength) {
            case 5 -> "Very Strong";
            case 4 -> "Strong";
            case 3 -> "Medium";
            case 2 -> "Weak";
            default -> "Very Weak";
        };
    }
}
