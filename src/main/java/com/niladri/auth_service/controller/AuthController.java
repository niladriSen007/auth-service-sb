package com.niladri.auth_service.controller;

import com.niladri.auth_service.dto.LoginDto;
import com.niladri.auth_service.dto.LoginResponseDto;
import com.niladri.auth_service.dto.SignupDto;
import com.niladri.auth_service.dto.UserResponseDto;
import com.niladri.auth_service.service.AuthService;
import com.niladri.auth_service.service.UserServiceImpl;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    //    private final JwtService jwtService;
    private final UserServiceImpl userService;
    private final AuthService authService;

    @Value("${deployment.env")
    private String deploymentEnv;

    @PostMapping("/signup")
    public ResponseEntity<UserResponseDto> signup(@RequestBody SignupDto signupDto) {
        log.info("Inside signup method");
        return ResponseEntity.ok(userService.signup(signupDto));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginDto loginDto, HttpServletResponse response) {
        LoginResponseDto loginResponseDto = authService.login(loginDto);
        Cookie cookie = new Cookie("refreshToken", loginResponseDto.getRefreshToken());
        cookie.setMaxAge(24 * 60 * 60);
        cookie.setHttpOnly(true);
        cookie.setSecure("prod".equals(deploymentEnv));
        response.addCookie(cookie);
        return ResponseEntity.ok(loginResponseDto);
    }


    @PostMapping("/refresh")
    public ResponseEntity<LoginResponseDto> refresh(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
//        String refreshToken="";
//        if (cookies != null) {
//            for (Cookie cookie : cookies) {
//                if (cookie.getName().equals("refreshToken")) {
//                    refreshToken = cookie.getValue();
//                }
//            }
//        }
        String refreshToken = Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equals("refreshToken"))
                .findFirst()
                .map(Cookie::getValue)
                .orElseThrow(() ->
                        new AuthenticationServiceException("Refresh token not found")
                );
        LoginResponseDto loginResponseDto = authService.refresh(refreshToken);

        return ResponseEntity.ok(loginResponseDto);
    }

}
