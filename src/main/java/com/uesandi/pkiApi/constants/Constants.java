package com.uesandi.pkiApi.constants;

public class Constants {
    //Keystore Constants
    public static final String KEYSTORE_TYPE = "JCEKS";
    public static final String PASSWORD = "Test";
    public static final String KEYSTORE_FILE_NAME = "keystore.jceks";
    public static final String CA_ALIAS = "ca";
    public static final String PRIVATE_KEY_ALIAS = "ca_private_key";

    //Certificate Generation Constants
    public final static String SIGNATURE_ALGORITHM = "SHA256WithRSAEncryption";
    public final static String BASIC_CONSTRAINTS_OID = "2.5.29.19";
    public final static String COMMON_NAME_SHORT = "CN=";
    public final static String SELFSIGN_ISSUER_NAME = "Unai Esandi";
    public final static String SELFSIGN_ISSUER = COMMON_NAME_SHORT + SELFSIGN_ISSUER_NAME;

    //Request Filter Constants
    public final static String API_KEY_HEADER = "X-API-Key";
    public final static String API_KEY_HEADER_VALUE = "9ddaa525-bfc2-4f74-92e0-43b7a028aee1";
}
