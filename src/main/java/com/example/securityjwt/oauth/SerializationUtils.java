package com.example.securityjwt.oauth;

import java.io.*;

// 직렬화/역직렬화 유틸 클래스
public class SerializationUtils {

    // Serializable 객체를 byte 배열로 직렬화
    public static byte[] serialize(Serializable obj) {
        // try-with-resources: 스트림을 자동으로 닫아 리소스 누수 방지
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bos)) {
            // ObjectOutputStream을 통해 객체 그래프를 바이너리 형태로 기록
            out.writeObject(obj);
            // ByteArrayOutputStream에 누적된 바이트를 그대로 반환
            return bos.toByteArray();
        } catch (IOException e) {
            // 체크 예외를 런타임 예외로 감싸 상위 호출부 단순화
            throw new IllegalStateException(e);
        }
    }

    // byte 배열을 원래 객체로 역직렬화
    @SuppressWarnings("unchecked")
    public static <T> T deserialize(byte[] bytes) {
        // 입력 바이트를 기반으로 역직렬화 수행
        try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
             ObjectInputStream in = new ObjectInputStream(bis)) {
            // readObject는 Object 반환 → 제네릭 캐스팅(호출부에서 타입 보장)
            return (T) in.readObject();
        } catch (IOException | ClassNotFoundException e) {
            // 스트림 손상, 클래스 불일치(버전/클래스패스 문제) 등은 런타임 예외로 래핑
            throw new IllegalStateException(e);
        }
    }
}
