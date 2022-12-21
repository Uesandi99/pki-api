package com.uesandi.pkiApi.controller;

import com.uesandi.pkiApi.utils.CertGenerationUtils;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

@RestController
@RequestMapping("/crypto")
public class RequestController {
    @Autowired
    public RequestController(){};

    @GetMapping("/ca")
    public String generateCACertificate(@RequestParam(name="common_name") String name) throws GeneralSecurityException, OperatorCreationException, IOException {
        X509Certificate certificate = CertGenerationUtils.selfSign(name);
        StringWriter sw = new StringWriter();

        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(certificate);
        }

        return sw.toString();
    }

    @GetMapping("/csr")
    public String issueCertificate(@RequestParam(name="csr") String csr){
        return "CSR: Test";
    }

    @GetMapping("/validate")
    public Boolean validateCertificate(@RequestParam(name="crt") String crt){
        return true;
    }
}
