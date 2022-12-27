package com.uesandi.pkiApi.utils;

import com.uesandi.pkiApi.constants.Constants;
import com.uesandi.pkiApi.exception.CertificateGenerationException;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Calendar;
import java.util.Date;

public class CertGenerationUtils {


    private CertGenerationUtils(){}

    public static KeyPair generateRSAKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));

        return kpGen.generateKeyPair();
    }

    public static X509Certificate generateCA(String subjectCN) throws CertificateGenerationException {
        X509Certificate finalCert;
        KeyPair keyPair;

        try {
            keyPair = generateRSAKeyPair();

            X500Name subjectName = new X500Name(Constants.COMMON_NAME_SHORT + subjectCN);
            X500Name issuerName = new X500Name(Constants.SELFSIGN_ISSUER);

            X509v3CertificateBuilder certificateBuilder = generateCertificateBuilder(subjectName, issuerName, keyPair.getPublic());

            BasicConstraints basicConstraints = new BasicConstraints(true);

            certificateBuilder.addExtension(new ASN1ObjectIdentifier(Constants.BASIC_CONSTRAINTS_OID), true, basicConstraints);

            ContentSigner contentSigner = new JcaContentSignerBuilder(Constants.SIGNATURE_ALGORITHM).build(keyPair.getPrivate());

            finalCert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));
        }catch(Exception e){
            throw new CertificateGenerationException("Error generating CA certificate.", e);
        }

        try{
            KeystoreUtils keystoreUtils = KeystoreUtils.getInstance();
            keystoreUtils.saveCertificate(finalCert);
            keystoreUtils.savePrivateKey(keyPair.getPrivate(), finalCert);
        }catch (KeyStoreException e){
            e.printStackTrace();
        }

        return finalCert;
    }

    public static X509Certificate issueCertificate(PKCS10CertificationRequest csr) throws CertificateGenerationException {
        X509Certificate x509Certificate;
        PrivateKey privateKey;
        try{
            x509Certificate = KeystoreUtils.getInstance().getCertificate();
            privateKey = KeystoreUtils.getInstance().getPrivateKey();
        }catch (KeyStoreException e){
            throw new CertificateGenerationException("Error reading Keystore file.", e);
        }

        if(x509Certificate == null || privateKey == null) throw new CertificateGenerationException("Missing information in Keystore file, please generate CA again.");

        X509Certificate finalCert;

        X500Name subjectName = csr.getSubject();
        X500Name issuerName = new X500Name(x509Certificate.getSubjectX500Principal().getName());

        try{
            SubjectPublicKeyInfo pkInfo = csr.getSubjectPublicKeyInfo();
            RSAKeyParameters rsa = (RSAKeyParameters) PublicKeyFactory.createKey(pkInfo);
            RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(rsa.getModulus(), rsa.getExponent());
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey rsaPub = kf.generatePublic(rsaSpec);

            X509v3CertificateBuilder certificateBuilder = generateCertificateBuilder(subjectName, issuerName, rsaPub);

            BasicConstraints basicConstraints = new BasicConstraints(true);

            certificateBuilder.addExtension(new ASN1ObjectIdentifier(Constants.BASIC_CONSTRAINTS_OID), true, basicConstraints);

            ContentSigner contentSigner = new JcaContentSignerBuilder(Constants.SIGNATURE_ALGORITHM).build(privateKey);

            finalCert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));

        }catch (Exception e){
            throw new CertificateGenerationException("Error issuing certificate.", e);
        }

        return finalCert;
    }

    public static Boolean verifyCertificate(X509Certificate certificate){
        boolean response = false;

        try{
            certificate.verify(KeystoreUtils.getInstance().getCertificate().getPublicKey());
            response = true;
        }catch (Exception ignored){
        }

        return response;
    }

    public static PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(String pemString) throws CertificateGenerationException {
        PKCS10CertificationRequest csr;
        ByteArrayInputStream pemStream = new ByteArrayInputStream(pemString.getBytes(StandardCharsets.UTF_8));

        Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
        PEMParser pemParser = null;
        try {
            pemParser = new PEMParser(pemReader);
            PemObject parsedObj = pemParser.readPemObject();
            csr = new PKCS10CertificationRequest(parsedObj.getContent());
        } catch (IOException e) {
            throw new CertificateGenerationException("Error parsing CSR from PEM.", e);
        } finally {
            if (pemParser != null) {
                IOUtils.closeQuietly(pemParser);
            }
        }
        return csr;
    }

    public static X509Certificate parseCertificateFromPem(String pem) throws CertificateException {
        ByteArrayInputStream pemStream = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8));

        return (X509Certificate) new CertificateFactory().engineGenerateCertificate(pemStream);
    }

    private static X509v3CertificateBuilder generateCertificateBuilder(X500Name subjectName, X500Name issuerName, PublicKey publicKey){
        //Prepare dates
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        //Generate Serial Number from current time
        BigInteger certSerialNumber = new BigInteger(String.valueOf(now));

        return new JcaX509v3CertificateBuilder(issuerName, certSerialNumber, startDate, endDate, subjectName, publicKey);
    }
}
