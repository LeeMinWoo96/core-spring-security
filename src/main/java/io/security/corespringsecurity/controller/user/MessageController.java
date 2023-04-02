package io.security.corespringsecurity.controller.user;


import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {

    @GetMapping("/message")
    public String message(){
        return "user/messages";
    }


    @PostMapping("/api/message")
    @ResponseBody
    public String apiMessage(){
//        return ResponseEntity.ok().body("ok");
        return "message_ok";
    }
}
