package com.uesandi.pkiApi.utils;

import com.uesandi.pkiApi.constants.Constants;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class KeystoreUtils {
    private static KeystoreUtils instance;
    private KeyStore keyStore;


    private KeystoreUtils() throws KeyStoreException {
        boolean keystoreExists = true;
        keyStore = KeyStore.getInstance(Constants.KEYSTORE_TYPE);
        FileInputStream stream = null;
        try{
            stream = new FileInputStream(Constants.KEYSTORE_FILE_NAME);
        }catch (FileNotFoundException e){
            keystoreExists = false;
        }
        try{
            if(keystoreExists) keyStore.load(stream, Constants.PASSWORD.toCharArray());
            else keyStore.load(null, Constants.PASSWORD.toCharArray());
        }catch (Exception e){
            throw new KeyStoreException("Error loading Keystore.", e);
        }
    }

    public static KeystoreUtils getInstance() throws KeyStoreException {
        if(instance == null) instance = new KeystoreUtils();
        return instance;
    }

    public void saveKeystore() throws KeyStoreException {
        try (FileOutputStream stream = new FileOutputStream(Constants.KEYSTORE_FILE_NAME)) {
            keyStore.store(stream, Constants.PASSWORD.toCharArray());
        }catch (Exception e){
            throw new KeyStoreException("Error saving Keystore into file.", e);
        }
    }

    public void saveCertificate(Certificate certificate) throws KeyStoreException {
        keyStore.setCertificateEntry(Constants.CA_ALIAS, certificate);
        saveKeystore();
    }

    public void savePrivateKey(PrivateKey privateKey, Certificate certificate) throws KeyStoreException {
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

    public PrivateKey getPrivateKey() throws KeyStoreException {
        Key key;
        try{
            key = keyStore.getKey(Constants.PRIVATE_KEY_ALIAS, Constants.PASSWORD.toCharArray());
        } catch (Exception e) {
            throw new KeyStoreException("Error recovering private key from Keystore.", e);
        }

        return (PrivateKey) key;
    }
}
