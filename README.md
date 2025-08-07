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

## 배포 주소
https://winner.store

## API 설명

| API             | Request Body                                     | Response                                                | 설명                             |
| --------------- | ------------------------------------------------ | ------------------------------------------------------- | ------------------------------ |
| `/auth/signup`  | `{ "username": "string", "password": "string" }` | `{"success": false,"message": "이미 존재하는 사용자입니다. or 회원가입성공","data": null}` | 신규 사용자 회원가입                    |
| `/auth/login`   | `{ "username": "string", "password": "string" }` | `{"success": true,"message": "로그인 성공","data": {"accessToken": "","refreshToken": ""}}`| 로그인 성공 시 JWT 발급                |
| `/auth/refresh` | `{"refreshToken": "{{refreshToken}}"}` | `{"success": true,"message": "토큰 재발급 성공","data": "토큰값"}` | RefreshToken으로 AccessToken 재발급 |
| `/user/me`      | Header: `Authorization: Bearer {accessToken}`    |  `{"success": true,"message": "유저 정보 조회 결과","data": {"id": 1,"username": "testuser","password": "비번","refreshToken" : "토큰값","enabled": true,"roles": [],"accountNonExpired": true,"accountNonLocked": true,"credentialsNonExpired": true}}`     | 인증된 사용자 정보 반환                  |


## 기타(참고url,기술오류 등등)
postman : https://www.postman.com/backend-team-b/spring-security-jwt/collection/l1adr0w/jwt?action=share&source=copy-link&creator=46095284
