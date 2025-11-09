package com.bankinghub.backend.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

/**
 * Base entity class providing audit trail functionality.
 * <p>
 * All entities extending this class automatically track creation and modification
 * metadata including timestamps and user information through JPA auditing.
 * </p>
 * 
 * @author Melvin Musonda Chibanda
 * @version 2.0.0
 * @since 2.0.0
 */
@Getter
@Setter
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseEntity {

    /** Timestamp when the entity was created */
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /** Timestamp when the entity was last updated */
    @LastModifiedDate
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    /** Email of the user who created the entity */
    @CreatedBy
    @Column(name = "created_by", updatable = false)
    private String createdBy;

    /** Email of the user who last modified the entity */
    @LastModifiedBy
    @Column(name = "last_modified_by")
    private String lastModifiedBy;

    /**
     * JPA lifecycle callback executed before entity persistence.
     * Sets creation and update timestamps.
     */
    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        updatedAt = LocalDateTime.now();
    }

    /**
     * JPA lifecycle callback executed before entity update.
     * Updates the modification timestamp.
     */
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
