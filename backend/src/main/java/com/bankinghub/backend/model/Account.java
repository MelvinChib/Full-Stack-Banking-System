package com.bankinghub.backend.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Account entity representing a bank account.
 * <p>
 * This entity stores account information including balance, account type,
 * and relationships to transactions and transfers. Supports multiple account
 * types: CHECKING, SAVINGS, CREDIT_CARD, LOAN, and INVESTMENT.
 * </p>
 * 
 * @author Melvin Musonda Chibanda
 * @version 2.0.0
 * @since 1.0.0
 */
@Entity
@Table(name = "accounts", indexes = {
    @Index(name = "idx_account_number", columnList = "accountNumber", unique = true),
    @Index(name = "idx_account_user", columnList = "user_id"),
    @Index(name = "idx_account_type", columnList = "accountType"),
    @Index(name = "idx_account_active", columnList = "active")
})
@Data
@EqualsAndHashCode(exclude = {"transactions", "fromTransfers", "toTransfers"})
@ToString(exclude = {"transactions", "fromTransfers", "toTransfers"})
@EntityListeners(AuditingEntityListener.class)
public class Account extends BaseEntity {

    /** Unique identifier for the account */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Unique account number (e.g., MBZ1234567890) */
    @Column(nullable = false, unique = true, length = 20)
    private String accountNumber;

    /** Type of account (CHECKING, SAVINGS, CREDIT_CARD, LOAN, INVESTMENT) */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AccountType accountType;

    /** Current account balance */
    @Column(nullable = false, precision = 15, scale = 2)
    private BigDecimal balance = BigDecimal.ZERO;

    /** User-friendly name for the account */
    @Column(nullable = false, length = 100)
    private String accountName;

    /** Optional description of the account */
    @Column(length = 255)
    private String description;

    /** Whether the account is active */
    @Column(nullable = false)
    private Boolean active = true;

    /** Credit limit for credit card accounts */
    @Column(precision = 15, scale = 2)
    private BigDecimal creditLimit;

    /** Interest rate for savings/loan accounts */
    @Column(precision = 5, scale = 4)
    private BigDecimal interestRate;

    /** Timestamp when the account was created */
    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /** Timestamp when the account was last updated */
    @LastModifiedDate
    private LocalDateTime updatedAt;

    /** Owner of this account */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /** List of transactions for this account */
    @OneToMany(mappedBy = "account", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Transaction> transactions;

    /** List of transfers originating from this account */
    @OneToMany(mappedBy = "fromAccount", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Transfer> fromTransfers;

    /** List of transfers received by this account */
    @OneToMany(mappedBy = "toAccount", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Transfer> toTransfers;

    /**
     * Account type enumeration.
     * <p>
     * Defines the different types of accounts supported by the system.
     * </p>
     */
    public enum AccountType {
        /** Standard checking account for daily transactions */
        CHECKING,
        /** Savings account with interest */
        SAVINGS,
        /** Credit card account with credit limit */
        CREDIT_CARD,
        /** Loan account */
        LOAN,
        /** Investment account */
        INVESTMENT
    }


}