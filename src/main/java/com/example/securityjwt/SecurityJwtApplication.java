package com.example.securityjwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.example.securityjwt")
public class SecurityJwtApplication {
	public static void main(String[] args) {
		SpringApplication.run(SecurityJwtApplication.class, args);
	}
}

