package com.uesandi.pkiApi;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Provider;
import java.security.Security;

@SpringBootApplication
public class PkiApiApplication {
    public static void main(String[] args) {
        //Add BouncyCastle Provider to Security
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        SpringApplication.run(PkiApiApplication.class, args);
    }
}
