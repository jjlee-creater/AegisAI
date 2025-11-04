package org.aegisai.controller;

import org.hibernate.jdbc.Expectation;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

    @GetMapping("/")
    public String main(){
    return "백엔드 서버";
    }

}
