package com.niladri.auth_service.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginResponseDto {
    private String token;
    private String name;
    private String email;
}
