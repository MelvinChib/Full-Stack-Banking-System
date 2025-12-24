package com.bankinghub.backend.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.List;

/**
 * User entity representing a banking system user.
 * <p>
 * This entity stores user information including authentication credentials,
 * personal details, and relationships to accounts, bills, and budgets.
 * Passwords are stored using BCrypt hashing with strength 12.
 * </p>
 * 
 * @author Melvin Musonda Chibanda
 * @version 2.0.0
 * @since 1.0.0
 */
@Entity
@Table(name = "users", indexes = {
    @Index(name = "idx_user_email", columnList = "email", unique = true),
    @Index(name = "idx_user_role", columnList = "role"),
    @Index(name = "idx_user_enabled", columnList = "enabled")
})
@Data
@EqualsAndHashCode(callSuper = false, exclude = {"accounts", "bills", "budgets"})
@ToString(exclude = {"accounts", "bills", "budgets"})
@EntityListeners(AuditingEntityListener.class)
public class User extends BaseEntity {

    /** Unique identifier for the user */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** User's first name */
    @Column(nullable = false, length = 100)
    private String firstName;

    /** User's last name */
    @Column(nullable = false, length = 100)
    private String lastName;

    /** User's email address (unique, used for login) */
    @Column(nullable = false, unique = true, length = 150)
    private String email;

    /** User's hashed password (BCrypt strength 12) */
    @Column(nullable = false)
    private String password;

    /** User's phone number (optional) */
    @Column(length = 20)
    private String phoneNumber;

    /** User's physical address (optional) */
    @Column(length = 255)
    private String address;

    /** Whether two-factor authentication is enabled */
    @Column(name = "two_fa_enabled", nullable = false)
    private Boolean twoFactorEnabled = false;

    /** Secret key for two-factor authentication */
    @Column(name = "two_fa_secret")
    private String twoFactorSecret;

    /** Whether the user account is enabled */
    @Column(nullable = false)
    private Boolean enabled = true;

    /** Whether the user account has not expired */
    @Column(nullable = false)
    private Boolean accountNonExpired = true;

    /** Whether the user account is not locked */
    @Column(nullable = false)
    private Boolean accountNonLocked = true;

    /** Whether the user credentials have not expired */
    @Column(nullable = false)
    private Boolean credentialsNonExpired = true;

    /** User's role in the system (USER or ADMIN) */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role = Role.USER;

    /** Timestamp when the user was created */
    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /** Timestamp when the user was last updated */
    @LastModifiedDate
    private LocalDateTime updatedAt;

    /** List of accounts owned by this user */
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Account> accounts;

    /** List of bills associated with this user */
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Bill> bills;

    /** List of budgets created by this user */
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Budget> budgets;

    /**
     * User role enumeration.
     * <p>
     * Defines the access level for users in the system.
     * </p>
     */
    public enum Role {
        /** Standard user with basic banking access */
        USER,
        /** Administrator with full system access */
        ADMIN
    }


}