package com.uesandi.pkiApi.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class KeystoreUtils {
    private static KeystoreUtils instance;
    private KeyStore keyStore;
    private static final String PASSWORD = "Test";
    private static final String KEYSTORE_NAME = "keystore.jceks";

    private static final String CA_ALIAS = "ca";
    private static final String PRIVATE_KEY_ALIAS = "ca_private_key";

    private KeystoreUtils() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        keyStore = KeyStore.getInstance("JCEKS");
        try{
            keyStore.load(new FileInputStream(KEYSTORE_NAME), PASSWORD.toCharArray());
        }catch (FileNotFoundException e){
            keyStore.load(null, null);
        }
    }

    public static KeystoreUtils getInstance() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        if(instance == null) instance = new KeystoreUtils();
        return instance;
    }

    public void saveKeystore() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        try (FileOutputStream stream = new FileOutputStream(KEYSTORE_NAME)) {
            keyStore.store(stream, PASSWORD.toCharArray());
        }
    }

    public void saveCertificate(Certificate certificate) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        keyStore.setCertificateEntry(CA_ALIAS, certificate);
        saveKeystore();
    }

    public void savePrivateKey(PrivateKey privateKey, Certificate certificate) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        Certificate[] certChain = new Certificate[1];
        certChain[0] = certificate;
        KeyStore.PrivateKeyEntry keyEntry = new KeyStore.PrivateKeyEntry(privateKey, certChain);
        KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(PASSWORD.toCharArray());
        keyStore.setEntry(PRIVATE_KEY_ALIAS, keyEntry, passwordProtection);
        saveKeystore();
    }

    public X509Certificate getCertificate() throws KeyStoreException {
        return (X509Certificate) keyStore.getCertificate(CA_ALIAS);
    }

    public PrivateKey getPrivateKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        Key key = keyStore.getKey(PRIVATE_KEY_ALIAS, PASSWORD.toCharArray());

        return (PrivateKey) key;
    }
}
