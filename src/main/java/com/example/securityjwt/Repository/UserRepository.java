package com.example.securityjwt.Repository;

import com.example.securityjwt.Entity.User;
import com.example.securityjwt.dto.UserResponse;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

// User 엔티티를 관리하는 JPA Repository 인터페이스 -> - Spring Data JPA가 자동으로 구현체를 생성
// JpaRepository<User, Long> : User 엔티티를 Long 타입 PK 기준으로 CRUD 처리해줌
public interface UserRepository extends JpaRepository<User, Long> {

    //@return값 :  Optional<User> (User가 존재하면 반환, 없으면 빈 Optional)
    Optional<User> findByUsername(String username);

    //username 중복 체크에 유용 (회원가입 시 사용)
    boolean existsByUsername(String username);

    // DTO 프로젝션: 엔티티 대신 바로 UserResponse DTO로 조회 (컨트롤러/서비스에서 곧장 응답에 사용 가능)
    @Query("select new com.example.securityjwt.dto.UserResponse(u.id, u.username) " +
            "from User u where u.username = :username")
    Optional<UserResponse> findUserResponseByUsername(@Param("username") String username);
}
