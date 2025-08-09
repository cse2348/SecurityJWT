package com.example.securityjwt.common;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

// 모든 Controller에서 발생하는 예외를 한 곳에서 처리해주는 클래스(전역 예외 처리기)

@RestControllerAdvice  // 전역 예외 처리기임을 선언 (모든 @RestController에 적용됨)
public class GlobalExceptionHandler {

    // 요청 본문(JSON) 파싱 실패 등 (잘못된 요청 포맷)
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<Object>> handleHttpMessageNotReadable(HttpMessageNotReadableException e) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.failure("요청 본문을 읽을 수 없습니다. JSON 포맷을 확인하세요.", null));
    }

    // @Valid 검증 실패 처리 (필드별 에러를 함께 내려줌)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Object>> handleValidation(MethodArgumentNotValidException e) {
        List<Map<String, Object>> errors = e.getBindingResult().getFieldErrors().stream()
                .map(fe -> {
                    Map<String, Object> m = new HashMap<>();
                    m.put("field", fe.getField());
                    m.put("message", fe.getDefaultMessage());
                    m.put("rejectedValue", fe.getRejectedValue());
                    return m;
                })
                .collect(Collectors.toList());

        Map<String, Object> body = new HashMap<>();
        body.put("message", "요청 값이 올바르지 않습니다.");
        body.put("errors", errors);

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.failure("검증 실패", body));
    }

    // 잘못된 파라미터/비밀번호 불일치 등 클라이언트 오류
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<Object>> handleIllegalArgument(IllegalArgumentException e) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.failure(e.getMessage(), null));
    }

    // 인증 실패(토큰 불일치, 만료 등 포함 가능)
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<Object>> handleAuthentication(AuthenticationException e) {
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.failure("인증에 실패했습니다: " + e.getMessage(), null));
    }

    // 인가 실패(권한 부족)
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<Object>> handleAccessDenied(AccessDeniedException e) {
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(ApiResponse.failure("접근 권한이 없습니다.", null));
    }

    // UsernameNotFoundException이 발생했을 때 처리하는 메서드(유저를 찾을 수 없을 때 발생하는 예외)
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ApiResponse<Object>> handleUserNotFound(UsernameNotFoundException e) {
        // 404 Not Found 상태 코드와 함께 실패 응답 반환
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.failure(e.getMessage(), null));
    }

    // 모든 Exception을 처리하는(가장 범위가 넓은 예외 처리기)
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Object>> handleException(Exception e) {
        // 500 Internal Server Error 상태 코드와 함께 실패 응답 반환
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.failure("서버 내부 오류가 발생했습니다.", null));
    }
}
