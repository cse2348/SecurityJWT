package com.example.securityjwt.repository;

import com.example.securityjwt.entity.User;
import com.example.securityjwt.dto.UserResponse;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

// User 엔티티를 관리하는 Spring Data JPA Repository -> JpaRepository<User, Long> : User 엔티티를 Long 타입 PK 기준으로 CRUD 제공
public interface UserRepository extends JpaRepository<User, Long> {

    // 로컬 로그인용 username으로 사용자 조회 (소셜 유저는 username이 null일 수 있음)
    Optional<User> findByUsername(String username);

    // username 중복 체크 (회원가입 시 사용)
    boolean existsByUsername(String username);

    // 이메일로 사용자 조회 (소셜 유저는 이메일이 없을 수 있음)
    Optional<User> findByEmail(String email);

    // 이메일 존재 여부 확인 (편의 메서드)
    boolean existsByEmail(String email);

    // 소셜 로그인 사용자 식별: (provider, providerId) 조합으로 조회
    Optional<User> findByProviderAndProviderId(String provider, String providerId);

    // username으로 UserResponse DTO 바로 조회 -> 엔티티 대신 DTO를 직접 반환하여 컨트롤러/서비스에서 곧장 응답 사용 가능
    @Query("select new com.example.securityjwt.dto.UserResponse(u.id, u.username) " +
            "from User u where u.username = :username")
    Optional<UserResponse> findUserResponseByUsername(@Param("username") String username);
}
