package com.example.authservicedemo.dto;

public record LoginRequest (
        String username,
        String password
) {}
