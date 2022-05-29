package com.kdt.prmgs.springsec.user;

public class LoginRequest {

    private final String principal;

    private final String credentials;


    public LoginRequest(String principal, String credentials) {

        this.principal = principal;
        this.credentials = credentials;
    }

    public String getPrincipal() {

        return principal;
    }

    public String getCredentials() {

        return credentials;
    }

    @Override
    public String toString() {
        return "LoginRequest{" +
                "principal='" + principal + '\'' +
                ", credentials='" + credentials + '\'' +
                '}';
    }
}
