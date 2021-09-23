package com.poc.websocket.controller;

import com.poc.websocket.dto.PayLoad;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;


@RestController
public class GreetingController {

    private final SimpMessagingTemplate template;

    public GreetingController(SimpMessagingTemplate template) {
        this.template = template;
    }

    @Scheduled(cron = "0/20 * * ? * *")
    public void getRootMailStatus() {
        System.out.println("getRootMailStatus ::::::::::");
        Date now = new Date();
        template.convertAndSend("/topic/greetings", new PayLoad("Hello, " + now.toString() + "!"));
    }
}
