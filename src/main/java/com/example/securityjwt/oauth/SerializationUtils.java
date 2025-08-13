package com.example.securityjwt.oauth;

import java.io.*;

// 직렬화/역직렬화 유틸 클래스
public class SerializationUtils {

    // Serializable 객체를 byte 배열로 직렬화
    public static byte[] serialize(Serializable obj) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeObject(obj);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    // byte 배열을 원래 객체로 역직렬화
    @SuppressWarnings("unchecked")
    public static <T> T deserialize(byte[] bytes) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
             ObjectInputStream in = new ObjectInputStream(bis)) {
            return (T) in.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new IllegalStateException(e);
        }
    }
}
