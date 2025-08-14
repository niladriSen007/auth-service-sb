package com.niladri.auth_service.handler;

import com.niladri.auth_service.entity.User;
import com.niladri.auth_service.mapper.ModelMapper;
import com.niladri.auth_service.service.JwtService;
import com.niladri.auth_service.service.UserServiceImpl;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {


    private final UserServiceImpl userServiceImpl;
    private final JwtService jwtService;

    @Value("${deployment.env}")
    private String deploymentEnv;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        DefaultOAuth2User user = (DefaultOAuth2User) token.getPrincipal();
        String email = user.getAttribute("email");

        User userDetails = userServiceImpl.loadUserByEmail(email);
        //if we don't have an existing user then we will create a new user
        if (userDetails == null) {
            User newUser = User.builder()
                    .email(email)
                    .name(user.getAttribute("name"))
                    .build();
            userDetails = userServiceImpl.save(newUser);
        }
        String accessToken = jwtService.generateJwtAccessToken(userDetails);
        String refreshToken = jwtService.generateJwtRefreshToken(userDetails);
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure("prod".equals(deploymentEnv));
        response.addCookie(cookie);

        String redirectUrl = "http://localhost:3000?accessToken=" + accessToken;
//        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
        response.sendRedirect(redirectUrl);
    }
}
