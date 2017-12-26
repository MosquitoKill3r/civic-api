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

    public Boolean getIsValid() {
        return isValid;
    }

    public UserDataRecord setIsValid(Boolean isValid) {
        this.isValid = isValid;
        return this;
    }

    public Boolean getIsOwner() {
        return isOwner;
    }

    public UserDataRecord setIsOwner(Boolean isOwner) {
        this.isOwner = isOwner;
        return this;
    }
}
