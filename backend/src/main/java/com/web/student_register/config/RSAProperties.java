package com.web.student_register.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class RSAProperties {
    @Value("${jwt.auth.private-key}")
    private String privateKey;
    @Value("${jwt.auth.public-key}")
    private String publicKey;

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }
}
