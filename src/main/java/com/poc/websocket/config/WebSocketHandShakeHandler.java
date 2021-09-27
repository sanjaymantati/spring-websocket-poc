package com.poc.websocket.config;

import com.poc.websocket.security.JwtTokenProvider;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.WebSocketHttpHeaders;
import org.springframework.web.socket.server.HandshakeFailureException;
import org.springframework.web.socket.server.HandshakeHandler;
import org.springframework.web.socket.server.support.DefaultHandshakeHandler;

import javax.servlet.http.HttpSession;
import java.security.Principal;
import java.util.List;
import java.util.Map;

@Component
public class WebSocketHandShakeHandler extends DefaultHandshakeHandler {


    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    protected Principal determineUser(ServerHttpRequest request, WebSocketHandler wsHandler, Map<String, Object> attributes) {
        try {
            WebSocketHttpHeaders headers = new WebSocketHttpHeaders(request.getHeaders());
            List<String> authorization = headers.get("Authorization");
            if(authorization!=null && !authorization.isEmpty()){
                String token = authorization.get(0).split(" ")[0];
                UserDetails userDetails = new User(jwtTokenProvider.getUsername(token), jwtTokenProvider.getUsername(token), true, false, false, false,
                        jwtTokenProvider.buildUserAuthority(jwtTokenProvider.getRoleList(token)));
                return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }
    /*


    public boolean (ServerHttpRequest serverHttpRequest,
                               ServerHttpResponse serverHttpResponse,
                               WebSocketHandler webSocketHandler, Map<String, Object> map)
            throws HandshakeFailureException {
        WebSocketHttpHeaders headers = new WebSocketHttpHeaders(serverHttpRequest.getHeaders());
        try {
            List<String> authorization = headers.get("Authorization");
            String accessToken = authorization.get(0).split(" ")[0];
            jwtTokenProvider.validateToken(accessToken);
        } catch (Exception e) {
            return false;
        }
        return true;
    }

*/


}
