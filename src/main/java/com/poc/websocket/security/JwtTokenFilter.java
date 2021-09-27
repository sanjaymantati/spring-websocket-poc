package com.poc.websocket.security;

import io.jsonwebtoken.JwtException;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtTokenFilter extends GenericFilterBean {
	private final JwtTokenProvider jwtTokenProvider;

	public JwtTokenFilter(JwtTokenProvider jwtTokenProvider) {
		this.jwtTokenProvider = jwtTokenProvider;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
			throws IOException, ServletException {
		HttpServletRequest rewq = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		String token = jwtTokenProvider.resolveToken((HttpServletRequest) req);
		if ((token != null && !token.isEmpty()) && checkAPIEndpoint(rewq)) {

			try {
				jwtTokenProvider.validateToken(token);
			} catch (JwtException | IllegalArgumentException e) {
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
				throw new SecurityException("Invalid JWT token", HttpStatus.UNAUTHORIZED);
			}
			Authentication auth = jwtTokenProvider.getAuthentication(token);
			SecurityContextHolder.getContext().setAuthentication(auth);
			setHeader(response, jwtTokenProvider.createNewToken(token));

		}
		filterChain.doFilter(req, res);

	}

	private void setHeader(HttpServletResponse response, String newToken) {
		response.setHeader("Authorization", newToken);
		response.setHeader("traceId", MDC.get("traceId"));
		response.setHeader("Access-Control-Expose-Headers", "Authorization");
	}

	private boolean checkAPIEndpoint(HttpServletRequest request) {
		return (!request.getServletPath().equals("actuator/logfile")
				&& !request.getServletPath().equals("/actuator/info")
				&& !request.getServletPath().equals("/actuator/health")
				&& !request.getServletPath().equals("/actuator/env"));
	}
}
