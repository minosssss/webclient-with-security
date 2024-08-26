package com.example.demo.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class ExternalApiService {


    private final WebClient webClient;



    public Mono<String> fetchExternalData() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return webClient.get()
                .uri("/todos/1")  // JSONPlaceholder의 샘플 데이터
                .retrieve()
                .bodyToMono(String.class);
    }

    @Transactional
    public String fetchExternalBlock() {
        return webClient.get()
                .uri("/todos/1")  // JSONPlaceholder의 샘플 데이터
                .retrieve()
                .bodyToMono(String.class).block();
    }
}
