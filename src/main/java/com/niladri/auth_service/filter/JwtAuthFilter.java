package com.niladri.auth_service.filter;

import com.niladri.auth_service.entity.User;
import com.niladri.auth_service.service.JwtService;
import com.niladri.auth_service.service.UserServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.Arrays;

@Component
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserServiceImpl userServiceImpl;
    private final HandlerExceptionResolver handlerExceptionResolver;

    public JwtAuthFilter(JwtService jwtService, UserServiceImpl userServiceImpl,
                         @Qualifier("handlerExceptionResolver") HandlerExceptionResolver handlerExceptionResolver) {
        this.jwtService = jwtService;
        this.userServiceImpl = userServiceImpl;
        this.handlerExceptionResolver = handlerExceptionResolver;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {


        try {// Get JWT from request headers
            final String requestTokenHeader = request.getHeader("Authorization");

            // Validate JWT with a secret key and verify
            if (requestTokenHeader == null || !requestTokenHeader.startsWith("Bearer ")) {
                filterChain.doFilter(request, response);
                return;
            }

            // Get jwt from the authorization header and user id from JWT
            String jwtToken = requestTokenHeader.substring(7);
            Long userId = jwtService.getUserIdFromToken(jwtToken);


            // if the userId is not null and the global security context is null then set the global security context
            if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // Get user details from user id
                User user = userServiceImpl.getUserDetailsById(userId);
                //create a new authentication object using Usernamepasswordauthenticationtoken class/provider
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

                // this will contain the user ip address, session id etc. that can be used in rate-limiting DDos attack
                usernamePasswordAuthenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                //set the global security context
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
            // pass the request to the next filter
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            handlerExceptionResolver.resolveException(request, response, null, e);
        }
    }
}
