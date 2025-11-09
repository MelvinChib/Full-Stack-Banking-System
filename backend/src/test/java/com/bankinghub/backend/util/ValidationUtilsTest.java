package com.bankinghub.backend.util;

import com.bankinghub.backend.config.SecurityProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ValidationUtilsTest {

    @Mock
    private SecurityProperties securityProperties;

    @Mock
    private SecurityProperties.Security security;

    @Mock
    private SecurityProperties.Security.PasswordStrength passwordStrength;

    private ValidationUtils validationUtils;

    @BeforeEach
    void setUp() {
        lenient().when(securityProperties.getSecurity()).thenReturn(security);
        lenient().when(security.getPasswordStrength()).thenReturn(passwordStrength);
        lenient().when(passwordStrength.getMinLength()).thenReturn(8);
        lenient().when(passwordStrength.isRequireUppercase()).thenReturn(true);
        lenient().when(passwordStrength.isRequireLowercase()).thenReturn(true);
        lenient().when(passwordStrength.isRequireDigit()).thenReturn(true);
        lenient().when(passwordStrength.isRequireSpecialChar()).thenReturn(true);

        validationUtils = new ValidationUtils(securityProperties);
    }

    @Test
    void isValidEmail_ValidEmail_ReturnsTrue() {
        assertTrue(validationUtils.isValidEmail("test@example.com"));
    }

    @Test
    void isValidEmail_InvalidEmail_ReturnsFalse() {
        assertFalse(validationUtils.isValidEmail("invalid-email"));
        assertFalse(validationUtils.isValidEmail(null));
    }

    @Test
    void isValidPassword_ValidPassword_ReturnsTrue() {
        assertTrue(validationUtils.isValidPassword("Password123!"));
    }

    @Test
    void isValidPassword_InvalidPassword_ReturnsFalse() {
        assertFalse(validationUtils.isValidPassword("short"));
        assertFalse(validationUtils.isValidPassword(null));
    }

    @Test
    void isValidAmount_ValidAmount_ReturnsTrue() {
        assertTrue(validationUtils.isValidAmount(BigDecimal.valueOf(100.00)));
    }

    @Test
    void isValidAmount_InvalidAmount_ReturnsFalse() {
        assertFalse(validationUtils.isValidAmount(BigDecimal.ZERO));
        assertFalse(validationUtils.isValidAmount(null));
    }

    @Test
    void isValidZambianPhoneNumber_ValidNumber_ReturnsTrue() {
        assertTrue(validationUtils.isValidZambianPhoneNumber("+260977123456"));
    }

    @Test
    void isValidZambianPhoneNumber_InvalidNumber_ReturnsFalse() {
        assertFalse(validationUtils.isValidZambianPhoneNumber("123456"));
        assertFalse(validationUtils.isValidZambianPhoneNumber(null));
    }

    @Test
    void containsSqlInjection_DetectsSqlInjection() {
        assertTrue(validationUtils.containsSqlInjection("SELECT * FROM users"));
        assertFalse(validationUtils.containsSqlInjection("normal text"));
    }

    @Test
    void containsXss_DetectsXss() {
        assertTrue(validationUtils.containsXss("<script>alert('xss')</script>"));
        assertFalse(validationUtils.containsXss("normal text"));
    }

    @Test
    void sanitizeInput_RemovesDangerousCharacters() {
        assertEquals("test", validationUtils.sanitizeInput("test<>"));
        assertNull(validationUtils.sanitizeInput(null));
    }

    @Test
    void getPasswordStrengthDescription_ReturnsCorrectStrength() {
        assertEquals("Very Strong", validationUtils.getPasswordStrengthDescription("VeryStrong123!@#"));
        assertEquals("Too short (minimum 8 characters)", validationUtils.getPasswordStrengthDescription("Short1!"));
    }
}
