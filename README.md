# Spring Security JWT 인증/인가 프로젝트

## 프로젝트 개요

* **트랙**: Spring Security + JWT 인증/인가 시스템 구현
* **목표**: JWT 기반 사용자 인증/인가 시스템 구현 및 API 보호
* **구현 범위**: 회원가입, 로그인, 토큰 재발급, 보호 API, 예외 핸들링까지 완성

## 기술 스택

| 항목        | 기술                   |
| --------- | -------------------- |
| Language  | Java 17              |
| Framework | Spring Boot 3.2      |
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


## API 설명

| API             | Request Body                                     | Response                                                | 설명                             |
| --------------- | ------------------------------------------------ | ------------------------------------------------------- | ------------------------------ |
| `/auth/signup`  | `{ "username": "string", "password": "string" }` | `201 Created`                                           | 신규 사용자 회원가입                    |
| `/auth/login`   | `{ "username": "string", "password": "string" }` | `{ "accessToken": "string", "refreshToken": "string" }` | 로그인 성공 시 JWT 발급                |
| `/auth/refresh` | `{ "refreshToken": "string" }`                   | `{ "accessToken": "string" }`                           | RefreshToken으로 AccessToken 재발급 |
| `/user/me`      | Header: `Authorization: Bearer {accessToken}`    | `{ "id": 1, "username": "string", "role": "USER" }`     | 인증된 사용자 정보 반환                  |


## 기타(참고url,기술오류 등등)