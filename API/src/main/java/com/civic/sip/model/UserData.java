package com.civic.sip.model;

import java.util.ArrayList;
import java.util.List;

public class UserData {
    private List<UserDataRecord> userDataRecords = new ArrayList<>();

    public List<UserDataRecord> getUserDataRecords() {
        return userDataRecords;
    }

    public UserData setUserDataRecords(List<UserDataRecord> userDataRecords) {
        this.userDataRecords = userDataRecords;
        return this;
    }
}
