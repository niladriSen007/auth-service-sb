package com.niladri.auth_service.service;

import com.niladri.auth_service.dto.SignupDto;
import com.niladri.auth_service.dto.UserResponseDto;
import com.niladri.auth_service.entity.User;
import com.niladri.auth_service.mapper.ModelMapper;
import com.niladri.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username).orElseThrow(() -> new BadCredentialsException("User not found"));
    }

    public User getUserDetailsById(Long id) {
        return userRepository.findById(id).orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    public UserResponseDto signup(SignupDto signupDto) {

        log.info("Inside signup method");

        //check if the user is already present in the database or not
        if (userRepository.findByEmail(signupDto.getEmail()).isPresent()) {
            throw new BadCredentialsException("User already exists with the email id");
        }

        signupDto.setPassword(passwordEncoder.encode(signupDto.getPassword()));
        return ModelMapper.mapToUserResponseDto(userRepository.save(ModelMapper.mapToUser(signupDto)));
    }


}
