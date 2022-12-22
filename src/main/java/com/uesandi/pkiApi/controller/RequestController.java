package com.uesandi.pkiApi.controller;

import com.uesandi.pkiApi.utils.CertGenerationUtils;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@RestController
@RequestMapping("/crypto")
public class RequestController {
    @Autowired
    public RequestController(){};

    @GetMapping("/ca")
    public String generateCACertificate(@RequestParam(name="common_name") String name) throws GeneralSecurityException, OperatorCreationException, IOException {
        X509Certificate certificate = CertGenerationUtils.generateCA(name);
        StringWriter sw = new StringWriter();

        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(certificate);
        }

        return sw.toString();
    }

    @GetMapping("/crt")
    public String issueCertificate(@RequestParam(name="csr") String csr) throws IOException, GeneralSecurityException, OperatorCreationException {
        PKCS10CertificationRequest csrObj = CertGenerationUtils.convertPemToPKCS10CertificationRequest(csr);
        X509Certificate certificate = CertGenerationUtils.issueCertificate(csrObj);
        StringWriter sw = new StringWriter();

        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(certificate);
        }

        return sw.toString();
    }

    @GetMapping("/validate")
    public Boolean validateCertificate(@RequestParam(name="crt") String crt) throws CertificateException {
        X509Certificate certificate = CertGenerationUtils.parseCertificateFromPem(crt);
        Boolean result = CertGenerationUtils.verifyCertificate(certificate);
        return result;
    }
}
