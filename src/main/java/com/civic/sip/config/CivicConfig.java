package com.civic.sip.config;

public class CivicConfig {
    private String applicationId;
    private String applicationSecret;
    private String privateKey;
    private String publicKey;
    private String environment;

    public CivicConfig(String applicationId,
                       String applicationSecret,
                       String privateKey,
                       String publicKey,
                       String environment) {
        this.applicationId = applicationId;
        this.applicationSecret = applicationSecret;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.environment = environment;
    }

    public String getApplicationId() {
        return applicationId;
    }

    public String getApplicationSecret() {
        return applicationSecret;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public String getEnvironment() {
        return environment;
    }

    public String getPublicKey() {
        return publicKey;
    }
}
