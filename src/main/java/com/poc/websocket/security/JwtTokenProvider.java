package com.poc.websocket.security;


import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenProvider {
    private static final String AUTH = "auth";
    private static final String LOGOUT_TIME = "logoutTime";
    private static final String LOCKSCREEN_TIME = "lockScreenTime";
    private static final String ROOT_COMPANY_ID = "rootCompanyId";
    private static final String ROOT_USER_ID = "rootUserId";
    private static final String ROOT_EMAIL = "rootEmail";
    private static final String AUTHORIZATION = "Authorization";
    private static final String USERNAME = "username";
    private static final String FNAME = "fname";
    private static final String LNAME = "lname";
    private static final String ORGNAME = "orgname";
    private static final String RENDOMSTRING = "uuid";
    private static final String USERTYPE = "userType";

    // SSO Authorization.
    private static final String USER_ID="user_id";
    private static final String CLIENT_ID="client_id";
    private static final String SCOPE="scope";
    private static final String ORG_ID="root_companies_id";
    private static final String TOKEN_TYPE="token_type";
    private static final String JTI="jti";


    @Value("${ENVIRONMENT}")
    private String environment;

    private String apiKey;

    @PostConstruct
    protected void init() {
        this.apiKey = "bfzweTeBetRpLwdbhk8GWyqsImii9U2Hadsfsafddf7HaJnEK7HjC89jC8CHJ^fadsfasdfA7S7Pi1CREXN0D67FHeJNzYHMmEGEpqfbznaoUSGQiTuhu";
        this.apiKey = Base64.getEncoder().encodeToString(this.apiKey.getBytes());
    }

    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION);
        Cookie[] cookielist = request.getCookies();

        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        if (bearerToken != null) {
            return bearerToken;
        }
        if (cookielist != null) {
            for (Cookie cookie : cookielist) {
                if (cookie.getName() != null && cookie.getName().equals("access_token") && cookie.getValue() != null
                        && !cookie.getValue().isEmpty()) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    public boolean validateToken(String token) throws JwtException, IllegalArgumentException {
        Jwts.parser().setSigningKey(apiKey).parseClaimsJws(token);
        return true;
    }

    public String getUsername(String token) {
        return (String) Jwts.parser().setSigningKey(apiKey).parseClaimsJws(token).getBody().get(USERNAME);
    }

    public String getFnameFromToken(String token) {
        return (String) Jwts.parser().setSigningKey(apiKey).parseClaimsJws(token).getBody().get(FNAME);
    }

    public String getLnameFromToken(String token) {
        return (String) Jwts.parser().setSigningKey(apiKey).parseClaimsJws(token).getBody().get(LNAME);
    }

    public String getOrgNameFromToken(String token) {
        return (String) Jwts.parser().setSigningKey(apiKey).parseClaimsJws(token).getBody().get(ORGNAME);
    }

    public String getUserTypeFromToken(String token) {
        return (String) Jwts.parser().setSigningKey(apiKey).parseClaimsJws(token).getBody().get(USERTYPE);
    }

    @SuppressWarnings("unchecked")
    public List<String> getRoleList(String token) {
        return (List<String>) Jwts.parser().setSigningKey(apiKey).parseClaimsJws(token).getBody().get(AUTH);
    }

    public Integer getLogoutTimeFromToken(String token) {
        return (Integer) Jwts.parser().setSigningKey(apiKey).parseClaimsJws(token).getBody().get(LOGOUT_TIME);
    }

    public Integer getLockScreenTimeFromToken(String token) {
        return (Integer) Jwts.parser().setSigningKey(apiKey).parseClaimsJws(token).getBody().get(LOCKSCREEN_TIME);
    }

    public Integer getRootUserIdToken(String token) {
        return (Integer) Jwts.parser().setSigningKey(apiKey).parseClaimsJws(token).getBody().get(ROOT_USER_ID);
    }

    public String getRootEmailFromToken(String token) {
        return (String) Jwts.parser().setSigningKey(apiKey).parseClaimsJws(token).getBody().get(ROOT_EMAIL);
    }

    public Integer getRootCompanyIdFromToken(String token) {
        return (Integer) Jwts.parser().setSigningKey(apiKey).parseClaimsJws(token).getBody().get(ROOT_COMPANY_ID);
    }

    public List<GrantedAuthority> buildUserAuthority(List<String> authorityList) {
        Set<GrantedAuthority> setAuths = new HashSet<GrantedAuthority>();
        for (String authority : authorityList) {
            setAuths.add(new SimpleGrantedAuthority("ROLE_" + authority));
        }
        List<GrantedAuthority> result = new ArrayList<>(setAuths);
        return result;
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails = new User(getUsername(token), getUsername(token), true, false, false, false,
                buildUserAuthority(getRoleList(token)));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public Date getIssuedAt(String token) {
        return Jwts.parser().setSigningKey(apiKey).parseClaimsJws(token).getBody().getIssuedAt();
    }

    public String getUUIDFromToken(String token) {
        return (String) Jwts.parser().setSigningKey(apiKey).parseClaimsJws(token).getBody().get(RENDOMSTRING);
    }

    public String getUUID() {
        StringBuilder newToken = new StringBuilder("kpi-");
        newToken.append(UUID.randomUUID().toString()).append("-");
        newToken.append(new Timestamp(System.currentTimeMillis()).getTime());
        return newToken.toString();
    }


    public String createToken(String username, List<String> roles) {

        Claims claims = Jwts.claims().setSubject(username);
        claims.put(AUTH, roles);
        claims.put(LOGOUT_TIME, 30l);
        claims.put(LOCKSCREEN_TIME, 15l);
        claims.put(ROOT_USER_ID, 8l);
        claims.put(ROOT_EMAIL, "naren@kpininja.com");
        claims.put(ROOT_COMPANY_ID, 2l);
        claims.put(USERNAME, username);
        claims.put(FNAME, "dev");
        claims.put(LNAME, "dev");
        claims.put(ORGNAME, "test org");
        claims.put(RENDOMSTRING, getUUID());

        Date now = new Date();
        Date validity = new Date(now.getTime() + 900000);
        return Jwts.builder()//
                .setClaims(claims)//
                .setIssuedAt(now)//
                .setExpiration(validity)//
                .signWith(SignatureAlgorithm.HS256, apiKey)//
                .compact();
    }

    /**
     * Author: KPI Ninja
     * Last modified by: Jatin
     *
     * @implNote : Create token with username, email and other details.
     * @since V4-SNAPSHOT
     *
     * @param username Username of user.
     * @param email  Email id of user.
     * @param roles Authorized roles.
     * @param userId User id of user.
     * @param companyId Id current organization of user.
     * @param lockscreenTime Lock screen time of organization of user.
     * @param logoutTime Logout time of organization of user.
     * @return JWT token.
     */
    public String createToken(String fname,String lname,String orgname,String username,String email,List<String> roles,Long userId,Long companyId,Long lockscreenTime,Long logoutTime) {
        Long validateLogoutTime = 15l;
        Long validatelockscreenTime = 30l;
        if(logoutTime != null && logoutTime >= 1l) {
            validateLogoutTime = logoutTime;
        }
        if(lockscreenTime != null && lockscreenTime >= 1l) {
            validatelockscreenTime = lockscreenTime;
        }

        Claims claims = Jwts.claims().setSubject(username);
        claims.put(AUTH, roles);
        claims.put(LOGOUT_TIME, validateLogoutTime);
        claims.put(LOCKSCREEN_TIME, validatelockscreenTime);
        claims.put(ROOT_USER_ID, userId);
        claims.put(ROOT_EMAIL, email);
        claims.put(ROOT_COMPANY_ID, companyId);
        claims.put(USERNAME, username);
        claims.put(FNAME, fname);
        claims.put(LNAME, lname);
        claims.put(ORGNAME, orgname);
        claims.put(RENDOMSTRING, getUUID());
        claims.put(USERTYPE, "NORMAL");

        Date now = new Date();
        Date validity = null;
        if(logoutTime != null && logoutTime >= 1l) {
            validity = new Date(now.getTime() + (logoutTime * 60 * 1000));
        }else {
            validity = new Date(now.getTime() + (15 * 60 * 1000));
        }
        return Jwts.builder()//
                .setClaims(claims)//
                .setIssuedAt(now)//
                .setExpiration(validity)//
                .signWith(SignatureAlgorithm.HS256, apiKey)//
                .compact();
    }

    public String createToken(String fname,String lname,String orgname,String username,String email,List<String> roles,Long userId,Long companyId,Long lockscreenTime,Long logoutTime,String userType) {
        Long validateLogoutTime = 15l;
        Long validatelockscreenTime = 30l;
        if(logoutTime != null && logoutTime >= 1l) {
            validateLogoutTime = logoutTime;
        }
        if(lockscreenTime != null && lockscreenTime >= 1l) {
            validatelockscreenTime = lockscreenTime;
        }

        Claims claims = Jwts.claims().setSubject(username);
        claims.put(AUTH, roles);
        claims.put(LOGOUT_TIME, validateLogoutTime);
        claims.put(LOCKSCREEN_TIME, validatelockscreenTime);
        claims.put(ROOT_USER_ID, userId);
        claims.put(ROOT_EMAIL, email);
        claims.put(ROOT_COMPANY_ID, companyId);
        claims.put(USERNAME, username);
        claims.put(FNAME, fname);
        claims.put(LNAME, lname);
        claims.put(ORGNAME, orgname);
        claims.put(RENDOMSTRING, getUUID());
        claims.put(USERTYPE, userType);

        Date now = new Date();
        Date validity = null;
        if(logoutTime != null && logoutTime >= 1l) {
            validity = new Date(now.getTime() + (logoutTime * 60 * 1000));
        }else {
            validity = new Date(now.getTime() + (15 * 60 * 1000));
        }
        return Jwts.builder()//
                .setClaims(claims)//
                .setIssuedAt(now)//
                .setExpiration(validity)//
                .signWith(SignatureAlgorithm.HS256, apiKey)//
                .compact();
    }

    public String createNewToken(String token) {
        Integer validateLogoutTime = 15;
        Integer validatelockscreenTime = 30;
        if(getLogoutTimeFromToken(token) != null && getLogoutTimeFromToken(token) >= 1) {
            validateLogoutTime = getLogoutTimeFromToken(token);
        }
        if(getLockScreenTimeFromToken(token) != null && getLockScreenTimeFromToken(token) >= 1) {
            validatelockscreenTime = getLockScreenTimeFromToken(token);
        }

        Claims claims = Jwts.claims().setSubject(getUsername(token));
        claims.put(AUTH, getRoleList(token));
        claims.put(LOGOUT_TIME, validateLogoutTime);
        claims.put(LOCKSCREEN_TIME, validatelockscreenTime);
        claims.put(ROOT_USER_ID, getRootUserIdToken(token));
        claims.put(ROOT_EMAIL, getRootEmailFromToken(token));
        claims.put(ROOT_COMPANY_ID, getRootCompanyIdFromToken(token));
        claims.put(USERNAME, getUsername(token));
        claims.put(FNAME, getFnameFromToken(token));
        claims.put(LNAME, getLnameFromToken(token));
        claims.put(ORGNAME, getOrgNameFromToken(token));
        claims.put(RENDOMSTRING, getUUIDFromToken(token));
        claims.put(USERTYPE, getUserTypeFromToken(token));

        Date now = new Date();
        Date validity = null;
        if(getLogoutTimeFromToken(token) != null && getLogoutTimeFromToken(token) > 1l) {
            validity = new Date(now.getTime() + (getLogoutTimeFromToken(token) * 60 * 1000));
        }else {
            validity = new Date(now.getTime() + (15 * 60 * 1000));
        }
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, apiKey)
                .compact();
    }

    public String createVendorToken(String fname,String lname,String orgname,String username,String email, List<String> roles,Long userId,Long companyId,Long lockscreenTime,Long logoutTime) {

        Long validateLogoutTime = 15l;
        Long validatelockscreenTime = 30l;
        if(logoutTime != null && logoutTime >= 1l) {
            validateLogoutTime = logoutTime;
        }
        if(lockscreenTime != null && lockscreenTime >= 1l) {
            validatelockscreenTime = lockscreenTime;
        }

        Claims claims = Jwts.claims().setSubject(username);
        claims.put(AUTH, roles);
        claims.put(LOGOUT_TIME, validateLogoutTime);
        claims.put(LOCKSCREEN_TIME, validatelockscreenTime);
        claims.put(ROOT_USER_ID, userId);
        claims.put(ROOT_EMAIL, email);
        claims.put(ROOT_COMPANY_ID, companyId);
        claims.put(USERNAME, username);
        claims.put(FNAME, fname);
        claims.put(LNAME, lname);
        claims.put(ORGNAME, orgname);
        claims.put(USERTYPE, "NORMAL");
        claims.put(RENDOMSTRING, getUUID());

        Date now = new Date();
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .signWith(SignatureAlgorithm.HS256, apiKey)
                .compact();
    }

    public String createVendorToken(String fname,String lname,String orgname,String username,String email, List<String> roles,Long userId,Long companyId,Long lockscreenTime,Long logoutTime,String userType) {

        Long validateLogoutTime = 15l;
        Long validatelockscreenTime = 30l;
        if(logoutTime != null && logoutTime >= 1l) {
            validateLogoutTime = logoutTime;
        }
        if(lockscreenTime != null && lockscreenTime >= 1l) {
            validatelockscreenTime = lockscreenTime;
        }

        Claims claims = Jwts.claims().setSubject(username);
        claims.put(AUTH, roles);
        claims.put(LOGOUT_TIME, validateLogoutTime);
        claims.put(LOCKSCREEN_TIME, validatelockscreenTime);
        claims.put(ROOT_USER_ID, userId);
        claims.put(ROOT_EMAIL, email);
        claims.put(ROOT_COMPANY_ID, companyId);
        claims.put(USERNAME, username);
        claims.put(FNAME, fname);
        claims.put(LNAME, lname);
        claims.put(ORGNAME, orgname);
        claims.put(USERTYPE, userType);
        claims.put(RENDOMSTRING, getUUID());

        Date now = new Date();
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .signWith(SignatureAlgorithm.HS256, apiKey)
                .compact();
    }
}
