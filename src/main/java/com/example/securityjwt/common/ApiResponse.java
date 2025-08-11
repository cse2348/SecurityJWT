package com.example.securityjwt.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// API 표준 응답 형식 클래스 -> 모든 컨트롤러에서 동일한 응답 구조를 제공하기 위해 사용 ; success, message, data 필드로 구성됨
// @param <T> 응답 데이터의 타입 (제네릭)
@Data // @Getter, @Setter, @ToString, @EqualsAndHashCode, @RequiredArgsConstructor를 한번에 생성해줌 (Lombok)
@NoArgsConstructor
@AllArgsConstructor // 모든 필드를 받는 생성자 생성
@JsonInclude(JsonInclude.Include.NON_NULL) // data가 null이면 JSON에 포함하지 않음 (응답을 깔끔하게)
public class ApiResponse<T> {

    private boolean success;  // API 요청 성공 여부 (true/false)
    private String message;   // 응답 메시지 (성공, 실패 이유 등)
    private T data;           // 응답 데이터 (제네릭 타입으로 어떤 데이터든 받을 수 있음)

    //  성공 응답 (데이터와 기본 메시지 "success") -> 단순히 요청이 성공했음을 알리고, 결과 데이터를 함께 반환할 때 사용
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(true, "success", data);
    }

    //  성공 응답 (데이터와 커스텀 메시지) -> 요청이 성공했지만 기본 메시지가 아닌 다른 성공 메시지를 주고 싶을 때 사용
    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse<>(true, message, data);
    }

    //  실패 응답 (데이터 없이) -> 요청이 실패했을 때, 이유 메시지만 전달
    public static <T> ApiResponse<T> failure(String message) {
        return new ApiResponse<>(false, message, null);
    }

    // 실패 응답 (데이터 포함) -> 요청이 실패했을 때, 메시지와 함께 에러 상세 정보나 검증 오류 등을 data에 담아 내려줄 때 사용
    public static <T> ApiResponse<T> failure(String message, T data) {
        return new ApiResponse<>(false, message, data);
    }
}
