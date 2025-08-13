package com.example.securityjwt.oauth;

import java.io.*;

public class SerializationUtils {
    public static byte[] serialize(Serializable obj) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeObject(obj);
            return bos.toByteArray();
        } catch (IOException e) { throw new IllegalStateException(e); }
    }

    @SuppressWarnings("unchecked")
    public static <T> T deserialize(byte[] bytes) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
             ObjectInputStream in = new ObjectInputStream(bis)) {
            return (T) in.readObject();
        } catch (IOException | ClassNotFoundException e) { throw new IllegalStateException(e); }
    }
}
