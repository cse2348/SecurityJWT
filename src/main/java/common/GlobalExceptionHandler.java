package common;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

// 모든 Controller에서 발생하는 예외를 한 곳에서 처리해주는 클래스(전역 예외 처리기)

@RestControllerAdvice  //전역 예외 처리기임을 선언 (모든 @RestController에 적용됨)
public class GlobalExceptionHandler {

    // 모든 Exception을 처리하는 (가장 범위가 넓은 예외 처리기)
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<String>> handleException(Exception e) {
        // 500 Internal Server Error 상태 코드와 함께 실패 응답 반환
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiResponse<>(false, e.getMessage(), null));
    }

    // UsernameNotFoundException이 발생했을 때 처리하는 메서드(유저를 찾을 수 없을 때 발생하는 예외)
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ApiResponse<String>> handleUserNotFound(UsernameNotFoundException e) {
        // 404 Not Found 상태 코드와 함께 실패 응답 반환
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(new ApiResponse<>(false, e.getMessage(), null));
    }
}
