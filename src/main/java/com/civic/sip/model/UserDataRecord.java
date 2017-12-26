package com.civic.sip.model;

public class UserDataRecord {
    private String label;
    private String value;
    private Boolean isValid;
    private Boolean isOwner;

    public String getLabel() {
        return label;
    }

    public UserDataRecord setLabel(String label) {
        this.label = label;
        return this;
    }

    public String getValue() {
        return value;
    }

    public UserDataRecord setValue(String value) {
        this.value = value;
        return this;
    }

    public Boolean getValid() {
        return isValid;
    }

    public UserDataRecord setValid(Boolean valid) {
        isValid = valid;
        return this;
    }

    public Boolean getOwner() {
        return isOwner;
    }

    public UserDataRecord setOwner(Boolean owner) {
        isOwner = owner;
        return this;
    }
}
