package com.uesandi.pkiApi.model;

import org.bouncycastle.asn1.x500.X500Name;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public class CertificateAuthority {
    private X509Certificate certificate;
    private KeyPair keyPair;
    private X500Name name;

    public CertificateAuthority(X509Certificate certificate, KeyPair keyPair, X500Name name) {
        this.certificate = certificate;
        this.keyPair = keyPair;
        this.name = name;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public X500Name getName() {
        return name;
    }

    public void setName(X500Name name) {
        this.name = name;
    }
}
