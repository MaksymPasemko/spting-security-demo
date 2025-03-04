package com.ltp.springsecuritydemo.controller;

import com.ltp.springsecuritydemo.model.User;
import com.ltp.springsecuritydemo.service.JwtService;
import com.ltp.springsecuritydemo.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @PostMapping("register")
    public ResponseEntity<User> register(@RequestBody final User user){
        final User savedUser = userService.saveUser(user);
        return ResponseEntity.ok(savedUser);
    }

    @PostMapping("login")
    public ResponseEntity<?> login(@RequestBody final User user){
         final UsernamePasswordAuthenticationToken authenticationToken =
                 new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword());

         final Authentication authentication = authenticationManager.authenticate(authenticationToken);

         if(!authentication.isAuthenticated()){
             return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
         }

         final String token = jwtService.generateToken(user.getUsername());
         return ResponseEntity.ok(token);
    }
}
