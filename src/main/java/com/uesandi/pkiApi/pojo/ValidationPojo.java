package com.uesandi.pkiApi.pojo;

public class ValidationPojo {
    boolean valid;

    public ValidationPojo(){}

    public ValidationPojo(boolean valid) {
        this.valid = valid;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }
}
