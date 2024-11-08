package com.beanus.backend.contoller.user;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("/loginOauth")
@RequiredArgsConstructor
public class OAuth2Controller {


    @GetMapping
    public String requestDone(){
        System.out.println("OAuth2Controller");
        return "OK";
    }
}
