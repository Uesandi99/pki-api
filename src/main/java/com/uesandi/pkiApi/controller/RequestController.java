package com.uesandi.pkiApi.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/crypto")
public class RequestController {
    @Autowired
    public RequestController(){};

    @GetMapping("/ca")
    public String generateCACertificate(@RequestParam(name="common_name") String name){
        return "Hello " + name + "!";
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
