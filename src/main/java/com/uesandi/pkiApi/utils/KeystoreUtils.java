package com.uesandi.pkiApi.utils;

import com.uesandi.pkiApi.constants.Constants;

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


    private KeystoreUtils() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        keyStore = KeyStore.getInstance(Constants.KEYSTORE_TYPE);
        try{
            keyStore.load(new FileInputStream(Constants.KEYSTORE_FILE_NAME), Constants.PASSWORD.toCharArray());
        }catch (FileNotFoundException e){
            keyStore.load(null, null);
        }
    }

    public static KeystoreUtils getInstance() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        if(instance == null) instance = new KeystoreUtils();
        return instance;
    }

    public void saveKeystore() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        try (FileOutputStream stream = new FileOutputStream(Constants.KEYSTORE_FILE_NAME)) {
            keyStore.store(stream, Constants.PASSWORD.toCharArray());
        }
    }

    public void saveCertificate(Certificate certificate) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        keyStore.setCertificateEntry(Constants.CA_ALIAS, certificate);
        saveKeystore();
    }

    public void savePrivateKey(PrivateKey privateKey, Certificate certificate) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        Certificate[] certChain = new Certificate[1];
        certChain[0] = certificate;
        KeyStore.PrivateKeyEntry keyEntry = new KeyStore.PrivateKeyEntry(privateKey, certChain);
        KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(Constants.PASSWORD.toCharArray());
        keyStore.setEntry(Constants.PRIVATE_KEY_ALIAS, keyEntry, passwordProtection);
        saveKeystore();
    }

    public X509Certificate getCertificate() throws KeyStoreException {
        return (X509Certificate) keyStore.getCertificate(Constants.CA_ALIAS);
    }

    public PrivateKey getPrivateKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        Key key = keyStore.getKey(Constants.PRIVATE_KEY_ALIAS, Constants.PASSWORD.toCharArray());

        return (PrivateKey) key;
    }
}
