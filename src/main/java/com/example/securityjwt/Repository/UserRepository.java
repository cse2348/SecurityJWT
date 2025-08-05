package com.example.securityjwt.Repository;

import com.example.securityjwt.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
// User 엔티티를 관리하는 JPA Repository 인터페이스 -> - Spring Data JPA가 자동으로 구현체를 생성
// JpaRepository<User, Long> : User 엔티티를 Long 타입 PK 기준으로 CRUD 처리해줌
public interface UserRepository extends JpaRepository<User, Long> {
    //@return값 :  Optional<User> (User가 존재하면 반환, 없으면 빈 Optional)
    Optional<User> findByUsername(String username);
}


