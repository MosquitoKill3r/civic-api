package com.civic.sip.model;

public class UserDataRecord {
    private String label;
    private String value;
    private Boolean valid;
    private Boolean owner;

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
        return valid;
    }

    public UserDataRecord setValid(Boolean valid) {
        this.valid = valid;
        return this;
    }

    public Boolean getOwner() {
        return owner;
    }

    public UserDataRecord setOwner(Boolean owner) {
        this.owner = owner;
        return this;
    }
}
