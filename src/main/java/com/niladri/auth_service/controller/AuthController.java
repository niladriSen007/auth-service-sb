package com.niladri.auth_service.controller;

import com.niladri.auth_service.dto.LoginDto;
import com.niladri.auth_service.dto.LoginResponseDto;
import com.niladri.auth_service.dto.SignupDto;
import com.niladri.auth_service.dto.UserResponseDto;
import com.niladri.auth_service.service.AuthService;
import com.niladri.auth_service.service.JwtService;
import com.niladri.auth_service.service.UserServiceImpl;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

//    private final JwtService jwtService;
    private final UserServiceImpl userService;
    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<UserResponseDto> signup(@RequestBody SignupDto signupDto) {
        return ResponseEntity.ok(userService.signup(signupDto));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginDto loginDto, HttpServletResponse response) {
        LoginResponseDto loginResponseDto = authService.login(loginDto);
        Cookie cookie = new Cookie("token", loginResponseDto.getToken());
        cookie.setMaxAge(24 * 60 * 60);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
        return ResponseEntity.ok(loginResponseDto);
    }

}
