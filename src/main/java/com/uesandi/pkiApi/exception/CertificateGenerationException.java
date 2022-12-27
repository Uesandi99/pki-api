package com.uesandi.pkiApi.exception;

public class CertificateGenerationException extends Exception{

    private static final long serialVersionUID = 1162074154307600214L;

    public CertificateGenerationException() {
        super();
    }

    public CertificateGenerationException(String msg) {
        super(msg);
    }

    public CertificateGenerationException(String message, Throwable cause) {
        super(message, cause);
    }

    public CertificateGenerationException(Throwable cause) {
        super(cause);
    }
}
