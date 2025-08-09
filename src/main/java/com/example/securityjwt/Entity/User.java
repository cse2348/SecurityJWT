package com.example.securityjwt.Entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@Entity
@Table(name = "users") // MySQL 등에서 user 는 예약어라 안전하게 별도 테이블명 사용
@Getter
@Setter
@NoArgsConstructor
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)  // Auto Increment
    private Long id;

    @Column(nullable = false, unique = true, length = 50) // 아이디는 유니크/NOT NULL, 길이 제한
    private String username;  // 사용자명 (로그인 ID)

    @JsonIgnore // 응답에 노출되지 않도록
    @Column(nullable = false, length = 60) // BCrypt 해시 길이 보통 60
    private String password;  // 비밀번호 (암호화된 값)

    @JsonIgnore // 토큰도 외부 노출 금지
    @Column(length = 512) // 토큰 길이 여유있게
    private String refreshToken;  // 리프레시 토큰 저장 (로그인 시 저장, 재발급 시 검증)

    // 사용자 권한 반환 (지금은 권한 없이 빈 리스트)
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();  // 권한이 없는 경우 빈 리스트 반환
    }

    // 계정이 만료되지 않았는지 여부 (true면 만료되지 않음)
    @Override
    public boolean isAccountNonExpired() { return true; }

    // 계정이 잠기지 않았는지 여부 (true면 잠기지 않음)
    @Override
    public boolean isAccountNonLocked() { return true; }

    // 비밀번호가 만료되지 않았는지 여부 (true면 만료되지 않음)
    @Override
    public boolean isCredentialsNonExpired() { return true; }

    // 계정 활성화 여부 (true면 활성화)
    @Override
    public boolean isEnabled() { return true; }
}
