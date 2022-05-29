package com.kdt.prmgs.springsec.user;


import com.kdt.prmgs.springsec.jwt.JwtAuthentication;
import com.kdt.prmgs.springsec.jwt.JwtAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("api")
public class UserRestController {

    private final UserService userService;

    private final AuthenticationManager authenticationManager;

    public UserRestController(UserService userService, AuthenticationManager authenticationManager) {

        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping(path = "user/login")
    public UserDto login(@RequestBody LoginRequest request) {

        JwtAuthenticationToken authToken = new JwtAuthenticationToken(request.getPrincipal(), request.getCredentials());
        Authentication resultToken = authenticationManager.authenticate(authToken);
        JwtAuthenticationToken authenticated = (JwtAuthenticationToken) resultToken;
        JwtAuthentication principal = (JwtAuthentication) authenticated.getPrincipal();
        User user = (User) authenticated.getDetails();

        return new UserDto(principal.token, principal.username, user.getGroup().getName());
    }
}
