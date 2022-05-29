package com.kdt.prmgs.springsec.jwt;

import static org.apache.logging.log4j.util.Strings.isNotEmpty;
import static org.h2.mvstore.DataUtils.checkArgument;

public class JwtAuthentication {

    public final String token;

    public final String username;

    public JwtAuthentication(String token, String username) {
        checkArgument(isNotEmpty(token), "token must be provided");
        checkArgument(isNotEmpty(username), "token must be provided");

        this.token = token;
        this.username = username;
    }

    @Override
    public String toString() {
        return "JwtAuthentication{" +
                "token='" + token + '\'' +
                ", username='" + username + '\'' +
                '}';
    }
}
