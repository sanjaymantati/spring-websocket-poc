package com.poc.websocket.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
//@EnableWebSecurity(debug = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//
//        // Disable CSRF (cross site request forgery)
//        http.csrf().disable();
//        // Need ssl connection except in dev environment.
////		if(!"local".equalsIgnoreCase(environmentName)){
////			http.requiresChannel().anyRequest().requiresSecure();
////		}
//        http.cors().disable();
//        // No session will be created or used by spring security.
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//        // Entry points
//        http.authorizeRequests()
//                .antMatchers("/register-endpoint")
//                .permitAll()
//                // Disallow everything else..
//                .anyRequest().authenticated();
        ;
//
//        // If a user try to access a resource without having enough permissions
//        // Optional, if you want to test the API from a browser
        http.httpBasic().disable();
    }
}
