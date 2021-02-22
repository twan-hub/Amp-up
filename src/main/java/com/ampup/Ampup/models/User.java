package com.ampup.Ampup.models;

import com.sun.istack.NotNull;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.persistence.Entity;

@Entity
public class User extends AbstractEntity{

    @NotNull
    private String username;
    @NotNull
    private String passHash;

    private static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public User(){

    }

    public User(String username, String password) {
        this.username = username;
        this.passHash = encoder.encode(password);
    }

    public String getUsername() {
        return username;
    }

    public boolean isMatchingPassword(String password){
        return encoder.matches(password,passHash);
    }
}