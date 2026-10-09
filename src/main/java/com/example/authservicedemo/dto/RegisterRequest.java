package com.example.authservicedemo.dto;

public record RegisterRequest(
        String username,
        String email,
        String password,
        Long departmentId,
        String role
) {}
