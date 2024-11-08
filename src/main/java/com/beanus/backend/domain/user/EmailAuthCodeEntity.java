package com.beanus.backend.domain.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Data
@Table(name = "email_auth_code")
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailAuthCodeEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(nullable = false)
    private String email;
    @Column(nullable = false)
    private String authCode;
    @Column(columnDefinition = "boolean default false")
    private boolean isVerified;
    @CreationTimestamp
    private String createdDate;
    @UpdateTimestamp
    private String updatedDate;
}
