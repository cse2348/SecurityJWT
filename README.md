# Spring Security JWT 인증/인가 프로젝트

## 프로젝트 개요

* **트랙**: Spring Security + JWT 인증/인가 시스템 구현
* **목표**: JWT 기반 사용자 인증/인가 시스템 구현 및 API 보호
* **구현 범위**: 회원가입, 로그인, 토큰 재발급, 보호 API, 예외 핸들링까지 완성

## 기술 스택

| 항목        | 기술                   |
| --------- | -------------------- |
| Language  | Java 17              |
| Framework | Spring Boot 3      |
| Database  | MySQL                |
| Security  | Spring Security, JWT |
| Infra     | Docker, AWS EC2      |


## 기능 요약

| Endpoint        | Method | 설명                                    |
| --------------- | ------ | ------------------------------------- |
| `/auth/signup`  | POST   | 사용자 회원가입 (username, password 입력 후 저장) |
| `/auth/login`   | POST   | 로그인 후 AccessToken + RefreshToken 발급   |
| `/auth/refresh` | POST   | RefreshToken을 이용한 AccessToken 재발급     |
| `/user/me`      | GET    | JWT 인증된 사용자 정보 조회 (보호 API)            |
| `/oauth2/authorize/{provider}`       | GET    | 소셜 로그인 시작 (구글, 카카오, 네이버 중 선택)                      |
| `/oauth2/callback/{provider}`        | GET    | 소셜 로그인 성공 후 JWT 발급, 최초 로그인 시 자동 회원가입 처리       |
## 배포 주소
https://winnerteam.store

## API 설명

| API             | Request Body                                     | Response                                                | 설명                             |
| --------------- | ------------------------------------------------ | ------------------------------------------------------- | ------------------------------ |
| `/auth/signup`  | `{ "username": "string", "password": "string" }` | `{"success": false,"message": "이미 존재하는 사용자입니다. or 회원가입성공","data": null}` | 신규 사용자 회원가입                    |
| `/auth/login`   | `{ "username": "string", "password": "string" }` | `{"success": true,"message": "로그인 성공","data": {"accessToken": "","refreshToken": ""}}`| 로그인 성공 시 JWT 발급                |
| `/auth/refresh` | `{"refreshToken": "{{refreshToken}}"}` | `{"success": true,"message": "토큰 재발급 성공","data": "토큰값"}` | RefreshToken으로 AccessToken 재발급 |
| `/user/me`      | Header: `Authorization: Bearer {accessToken}`    |  `{"success": true,"message": "유저 정보 조회 결과","data": {"id": 1,"username": "testuser","password": "비번","refreshToken" : "토큰값","enabled": true,"roles": [],"accountNonExpired": true,"accountNonLocked": true,"credentialsNonExpired": true}}`     | 인증된 사용자 정보 반환                  |



#### 소셜 로그인 흐름
1. `/oauth2/authorize/{provider}` 요청 시 해당 플랫폼 로그인 페이지로 리다이렉트
2. 로그인 성공 후 `/oauth2/callback/{provider}` 로 인가 코드 전달
3. 서버에서 인가 코드로 Access Token 발급받아 사용자 정보 조회
4. DB에 사용자가 없으면 자동 회원가입 처리
5. JWT(Access + Refresh Token) 발급 후 반환

## 기타(참고url,기술오류 등등)
postman : https://www.postman.com/backend-team-b/spring-security-jwt/collection/l1adr0w/jwt?action=share&source=copy-link&creator=46095284

오류 발생 : 카카오 소셜 로그인 과정
1. 카카오 로그인 시작 → UNAUTHORIZED
원인: /oauth2/authorize/kakao와 같이 인증이 없는 상태에서 시작해야 하는 경로가 Spring Security의 JwtAuthenticationFilter에 의해 선제적으로 차단되고 있었음 (필터가 토큰이 없는 모든 요청을 '인증 실패'로 간주했기 때문)
해결: JwtAuthenticationFilter의 로직을 수정하여, Bearer 토큰이 없는 요청은 인증 처리 없이 다음 필터로 안전하게 통과시키도록 변경 -> 이로써 SecurityConfig의 .permitAll() 설정이 정상적으로 동작

2. 카카오 로그인 처리 중 → Duplicate entry (DB 오류)
원인: 카카오 로그인은 성공적으로 처리되었으나, 서버가 카카오로부터 받은 이메일가 DB에 이미 존재하는 것을 확인 ->  CustomOAuth2UserService의 로직이 이 경우에 기존 계정과 연동하지 않고, 새로운 계정을 생성(INSERT)하려고 시도하여 DB의 이메일 중복 방지 규칙(Unique Constraint)에 위배되어 오류 발생
해결: CustomOAuth2UserService의 로직을 수정 -> 소셜 로그인 시 전달받은 이메일이 DB에 이미 존재하면 새로 가입시키지 않고, 해당 계정에 소셜 로그인 정보(provider, providerId)를 업데이트하여 기존 계정과 연동하도록 변경하여 해결