package com.example.securityjwt.repository;

import com.example.securityjwt.entity.User;
import com.example.securityjwt.dto.UserResponse;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

// User 엔티티를 관리하는 Spring Data JPA Repository 인터페이스
// JpaRepository<User, Long> : User 엔티티를 Long 타입 PK 기준으로 CRUD 제공
// 메서드 네이밍 규칙으로 자동 쿼리 생성 (findBy..., existsBy... 등)
// 소셜 로그인 식별을 위한 (provider, providerId) 조회 메서드 추가
public interface UserRepository extends JpaRepository<User, Long> {
    // 로컬 로그인용 username으로 사용자 조회 -> 소셜 유저는 username이 null일 수 있음
    // @param username 로그인 ID 받고 -> @return Optional<User>
    Optional<User> findByUsername(String username);

    // username 중복 체크 (회원가입 시 사용) -> 소셜 유저는 username이 없을 수 있으므로, 로컬 가입 시에만 의미 있음
    // @param username 로그인 ID -> @return 존재 여부
    boolean existsByUsername(String username);

    // 이메일로 사용자 조회 -> 구글은 이메일이 잘 오지만, 카카오/네이버는 이메일이 없을 수 있음(null 허용 전략 필요)
    // @param email 이메일 -> @return Optional<User>
    Optional<User> findByEmail(String email);

    // 소셜 로그인 사용자 식별: (provider, providerId) 조합으로 조회-> 예) provider=KAKAO, providerId=카카오의 고유 사용자 ID
    // 최초 로그인 시 자동 회원가입 후, 재로그인 시 이 메서드로 조회
    // @param provider  GOOGLE/KAKAO/NAVER ,  providerId 소셜 고유 사용자 ID -> @return Optional<User>
    Optional<User> findByProviderAndProviderId(String provider, String providerId);

    /**
     * DTO 프로젝션 예시: 엔티티 대신 바로 UserResponse DTO로 조회
     * - 컨트롤러/서비스에서 곧장 응답에 사용 가능
     * - username으로 간단한 프로필 조회가 필요할 때 활용
     */
    @Query("select new com.example.securityjwt.dto.UserResponse(u.id, u.username) " +
            "from User u where u.username = :username")
    Optional<UserResponse> findUserResponseByUsername(@Param("username") String username);
}
