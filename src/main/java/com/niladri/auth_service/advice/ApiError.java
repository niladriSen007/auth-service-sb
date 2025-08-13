package com.niladri.auth_service.advice;

import java.time.LocalDate;

public class ApiError {
    private String message;
    private String status;
    private LocalDate timestamp;

    public ApiError() {
        this.timestamp = LocalDate.now();
    }

    public ApiError(String message, String status) {
        this();
        this.message = message;
        this.status = status;
    }
}
