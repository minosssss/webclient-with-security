package com.example.demo.controller;

import com.example.demo.service.ExternalApiService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ApiController {

    private final ExternalApiService externalApiService;

    @GetMapping("/public/hello")
    public String publicHello() {
        return "Hello, public!";
    }

    @GetMapping("/private/data")
    public Mono<String> privateData() {
        return externalApiService.fetchExternalData();
    }

    @GetMapping("/private/block")
    public String privateDataBlock() {
        return externalApiService.fetchExternalBlock();
    }
}
