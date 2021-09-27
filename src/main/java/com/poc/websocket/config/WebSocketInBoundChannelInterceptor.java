package com.poc.websocket.config;

import com.poc.websocket.security.JwtTokenProvider;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageHeaderAccessor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class WebSocketInBoundChannelInterceptor implements ChannelInterceptor {

    private final JwtTokenProvider jwtTokenProvider;


    public WebSocketInBoundChannelInterceptor(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }


    @Override
    public Message<?> preSend(Message<?> message, MessageChannel channel) {
        StompHeaderAccessor accessor = MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);
        if (StompCommand.CONNECT.equals(accessor.getCommand())) {
            List<String> authorization = accessor.getNativeHeader("Authorization");
            if(authorization!=null && !authorization.isEmpty()){
                String token = authorization.get(0).split(" ")[0];
                UserDetails userDetails = new User(jwtTokenProvider.getUsername(token), jwtTokenProvider.getUsername(token), true, false, false, false,
                        jwtTokenProvider.buildUserAuthority(jwtTokenProvider.getRoleList(token)));
                accessor.setUser(new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities()));
            }
        }
        return message;
    }

    @Override
    public void postSend(Message<?> message, MessageChannel channel, boolean sent) {
        System.out.println("postSend ::::::::::::::::::::::::::::::::");
        ChannelInterceptor.super.postSend(message, channel, sent);
    }

    @Override
    public void afterSendCompletion(Message<?> message, MessageChannel channel, boolean sent, Exception ex) {
        System.out.println("afterSendCompletion ::::::::::::::::::::::::::::::::");
        ChannelInterceptor.super.afterSendCompletion(message, channel, sent, ex);
    }

    @Override
    public boolean preReceive(MessageChannel channel) {
        System.out.println("preReceive ::::::::::::::::::::::::::::::::");
        return ChannelInterceptor.super.preReceive(channel);
    }

    @Override
    public Message<?> postReceive(Message<?> message, MessageChannel channel) {
        System.out.println("postReceive ::::::::::::::::::::::::::::::::");
        return ChannelInterceptor.super.postReceive(message, channel);
    }

    @Override
    public void afterReceiveCompletion(Message<?> message, MessageChannel channel, Exception ex) {
        System.out.println("afterReceiveCompletion ::::::::::::::::::::::::::::::::");
        ChannelInterceptor.super.afterReceiveCompletion(message, channel, ex);
    }
}
