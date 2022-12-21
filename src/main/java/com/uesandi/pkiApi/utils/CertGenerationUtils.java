package com.uesandi.pkiApi.utils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
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

    public static X509Certificate selfSign(String subjectCN) throws CertIOException, OperatorCreationException, GeneralSecurityException {
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

        return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certificateBuilder.build(contentSigner));
    }
}
