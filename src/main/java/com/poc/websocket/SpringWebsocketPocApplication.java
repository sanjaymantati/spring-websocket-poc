package com.poc.websocket;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.ComponentScans;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
public class SpringWebsocketPocApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringWebsocketPocApplication.class, args);
    }
}
