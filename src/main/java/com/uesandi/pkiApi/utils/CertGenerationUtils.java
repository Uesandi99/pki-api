package com.uesandi.pkiApi.utils;

import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.PEMUtil;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Calendar;
import java.util.Date;

public class CertGenerationUtils {
    final static String SIGNATURE_ALGORITHM = "SHA256WithRSAEncryption";
    final static String BASIC_CONSTRAINTS_OID = "2.5.29.19";
    private CertGenerationUtils(){}

    public static KeyPair generateRSAKeyPair() throws GeneralSecurityException
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));

        return kpGen.generateKeyPair();
    }

    public static X509Certificate generateCA(String subjectCN) throws CertIOException, OperatorCreationException, GeneralSecurityException {
        //Add BouncyCastle Provider to Security
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        KeyPair keyPair = generateRSAKeyPair();

        X500Name subjectName = new X500Name("CN=" + subjectCN);
        X500Name issuerName = new X500Name("CN=Unai Esandi");

        //Prepare dates
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        //Generate Serial Number from current time
        BigInteger certSerialNumber = new BigInteger(String.valueOf(now));

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(issuerName, certSerialNumber, startDate, endDate, subjectName, keyPair.getPublic());

        BasicConstraints basicConstraints = new BasicConstraints(true);

        certificateBuilder.addExtension(new ASN1ObjectIdentifier(BASIC_CONSTRAINTS_OID), true, basicConstraints);

        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(keyPair.getPrivate());

        X509Certificate finalCert = new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certificateBuilder.build(contentSigner));
        try{
            finalCert.verify(finalCert.getPublicKey());
            System.out.println(true);
        }catch (Exception e){
            System.out.println(false);
        }
        return finalCert;
    }

    public static X509Certificate issueCertificate(PKCS10CertificationRequest csr) throws CertIOException, OperatorCreationException, GeneralSecurityException {
        //Add BouncyCastle Provider to Security
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        KeyPair keyPair = generateRSAKeyPair();

        X500Name subjectName = new X500Name("CN=" + subjectCN);
        X500Name issuerName = new X500Name("CN=Unai Esandi");

        //Prepare dates
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        //Generate Serial Number from current time
        BigInteger certSerialNumber = new BigInteger(String.valueOf(now));

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(issuerName, certSerialNumber, startDate, endDate, subjectName, keyPair.getPublic());

        BasicConstraints basicConstraints = new BasicConstraints(true);

        certificateBuilder.addExtension(new ASN1ObjectIdentifier(BASIC_CONSTRAINTS_OID), true, basicConstraints);

        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(keyPair.getPrivate());

        X509Certificate finalCert = new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certificateBuilder.build(contentSigner));
        try{
            finalCert.verify(finalCert.getPublicKey());
            System.out.println(true);
        }catch (Exception e){
            System.out.println(false);
        }
        return finalCert;
    }
    public static PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(String pemString) throws IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        PKCS10CertificationRequest csr = null;
        ByteArrayInputStream pemStream = new ByteArrayInputStream(pemString.getBytes(StandardCharsets.UTF_8));

        Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
        PEMParser pemParser = null;
        try {
            pemParser = new PEMParser(pemReader);
            PemObject parsedObj = pemParser.readPemObject();
            csr = new PKCS10CertificationRequest(parsedObj.getContent());
            System.out.println("PemParser returned: " + parsedObj);
        } catch (IOException ex) {
        } finally {
            if (pemParser != null) {
                IOUtils.closeQuietly(pemParser);
            }
        }
        return csr;
    }
}
