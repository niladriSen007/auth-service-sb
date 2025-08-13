package com.niladri.auth_service.service;

import com.niladri.auth_service.dto.LoginDto;
import com.niladri.auth_service.dto.LoginResponseDto;
import com.niladri.auth_service.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {


    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public LoginResponseDto login(LoginDto loginDto) {
        Authentication auth = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken
                        (loginDto.getEmail(), loginDto.getPassword())
                );
        User user = (User) auth.getPrincipal();
        String jwtToken = jwtService.generateJwtToken(user);
        return LoginResponseDto.builder().email(user.getEmail()).name(user.getName()).token(jwtToken).build();
    }
}
