package com.niladri.auth_service.mapper;

import com.niladri.auth_service.dto.SignupDto;
import com.niladri.auth_service.dto.UserResponseDto;
import com.niladri.auth_service.entity.User;

public class ModelMapper {
    public static User mapToUser(SignupDto signupDto) {
          return User.builder()
                  .email(signupDto.getEmail())
                  .password(signupDto.getPassword())
                  .name(signupDto.getName())
                  .build();
    }

    public static UserResponseDto mapToUserResponseDto(User user) {
        return UserResponseDto.builder()
                .email(user.getEmail())
                .name(user.getName())
                .build();
    }
}
