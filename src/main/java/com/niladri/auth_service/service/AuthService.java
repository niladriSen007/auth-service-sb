package com.niladri.auth_service.service;

import com.niladri.auth_service.dto.LoginDto;
import com.niladri.auth_service.dto.LoginResponseDto;
import com.niladri.auth_service.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {


    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserServiceImpl userService;
    private final SessionService sessionService;

    public LoginResponseDto login(LoginDto loginDto) {
        Authentication auth = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken
                        (loginDto.getEmail(), loginDto.getPassword())
                );
        User user = (User) auth.getPrincipal();
        String jwtAccessToken = jwtService.generateJwtAccessToken(user);
        String jwtRefreshToken = jwtService.generateJwtRefreshToken(user);

        //create a new session for the user
        sessionService.generateNewSession(user,jwtRefreshToken);

        return LoginResponseDto.builder()
                .email(user.getEmail())
                .name(user.getName())
                .accessToken(jwtAccessToken)
                .refreshToken(jwtRefreshToken)
                .build();
    }

    public LoginResponseDto refresh(String refreshToken) {

        log.info("Inside refresh method");
        Long userId = jwtService.getUserIdFromToken(refreshToken);

        //check if the refresh token is valid or not
        sessionService.isSessionValid(refreshToken);

        User user = userService.getUserDetailsById(userId);



        String jwtAccessToken = jwtService.generateJwtAccessToken(user);
        return LoginResponseDto.builder()
                .email(user.getEmail())
                .name(user.getName())
                .accessToken(jwtAccessToken)
                .refreshToken(refreshToken)
                .build();

    }
}
