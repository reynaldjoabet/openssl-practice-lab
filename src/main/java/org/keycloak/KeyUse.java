package org.keycloak;

public enum KeyUse {

    SIG("sig"),
    ENC("enc"),
    JWT_SVID("jwt-svid");

    private String specName;

    KeyUse(String specName) {
        this.specName = specName;
    }

    public String getSpecName() {
        return specName;
    }

}
