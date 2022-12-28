package com.uesandi.pkiApi.controller;

import com.uesandi.pkiApi.exception.CertificateGenerationException;
import com.uesandi.pkiApi.pojo.CertificatePojo;
import com.uesandi.pkiApi.pojo.CommonNamePojo;
import com.uesandi.pkiApi.pojo.CsrPojo;
import com.uesandi.pkiApi.pojo.ValidationPojo;
import com.uesandi.pkiApi.utils.CertGenerationUtils;
import com.uesandi.pkiApi.utils.KeystoreUtils;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@RestController
@RequestMapping("/crypto")
public class RequestController {
    @Autowired
    public RequestController(){}

    @PostMapping (value = "/ca",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE)
    public CertificatePojo generateCACertificate(@RequestBody CommonNamePojo name) throws CertificateGenerationException, IOException, KeyStoreException {
        KeystoreUtils keystoreUtils = KeystoreUtils.getInstance();
        X509Certificate certificate = CertGenerationUtils.generateCA(name.getCommon_name());
        StringWriter sw = new StringWriter();

        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(certificate);
        }
        keystoreUtils.saveKeystore();

        return new CertificatePojo(sw.toString());
    }

    @PostMapping(value = "/crt",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public CertificatePojo issueCertificate(@RequestBody CsrPojo csr) throws IOException, CertificateGenerationException {
        PKCS10CertificationRequest csrObj = CertGenerationUtils.convertPemToPKCS10CertificationRequest(csr.getCsr());
        X509Certificate certificate = CertGenerationUtils.issueCertificate(csrObj);
        StringWriter sw = new StringWriter();

        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(certificate);
        }

        return new CertificatePojo(sw.toString());
    }

    @PostMapping(value = "/validate",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ValidationPojo validateCertificate(@RequestBody CertificatePojo crt) throws CertificateException {
        X509Certificate certificate = CertGenerationUtils.parseCertificateFromPem(crt.getCrt());
        return new ValidationPojo(CertGenerationUtils.verifyCertificate(certificate));
    }
}
