package com.sparta.springauth.auth;

import com.sparta.springauth.entity.UserRoleEnum;
import com.sparta.springauth.jwt.JwtUtil;
import io.jsonwebtoken.Claims; // ★ 잊지 말고 추가
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

@RestController
@RequestMapping("/api")
public class AuthController {

    // ★ 중복 선언 금지: 한 번만 선언
    public static final String AUTHORIZATION_HEADER = "Authorization";

    private final JwtUtil jwtUtil;

    public AuthController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/create-jwt")
    public String createJwt(HttpServletResponse res) {
        // Jwt 생성
        String token = jwtUtil.createToken("Robbie", UserRoleEnum.USER);

        // Jwt 쿠키 저장
        jwtUtil.addJwtToCookie(token, res);

        return "createJwt : " + token;
    }

    @GetMapping("/get-jwt")
    public String getJwt(
            // ★ 쿠키가 없으면 400 나던 문제 방지
            @CookieValue(name = JwtUtil.AUTHORIZATION_HEADER, required = false) String tokenValue) {

        if (tokenValue == null || tokenValue.isBlank()) {
            return "getJwt : 쿠키 없음";
        }

        String token = jwtUtil.substringToken(tokenValue);

        if (!jwtUtil.validateToken(token)) {
            throw new IllegalArgumentException("Token Error");
        }

        Claims info = jwtUtil.getUserInfoFromToken(token);
        String username = info.getSubject();
        String authority = (String) info.get(JwtUtil.AUTHORIZATION_KEY);

        return "getJwt : " + username + ", " + authority;
    }

    @GetMapping("/create-cookie")
    public String createCookie(HttpServletResponse res) {
        addCookie("Robbie Auth", res);
        return "createCookie";
    }

    @GetMapping("/get-cookie")
    public String getCookie(
            // ★ 쿠키 optional 처리
            @CookieValue(name = AUTHORIZATION_HEADER, required = false) String value) {
        return "getCookie : " + (value == null ? "" : value);
    }

    @GetMapping("/create-session")
    public String createSession(HttpServletRequest req) {
        HttpSession session = req.getSession(true);
        session.setAttribute(AUTHORIZATION_HEADER, "Robbie Auth");
        return "createSession";
    }

    @GetMapping("/get-session")
    public String getSession(HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        if (session == null) {
            return "getSession : 세션 없음";
        }
        String value = (String) session.getAttribute(AUTHORIZATION_HEADER);
        return "getSession : " + (value == null ? "" : value);
    }

    // 쿠키 생성
    public static void addCookie(String cookieValue, HttpServletResponse res) {
        try {
            cookieValue = URLEncoder.encode(cookieValue, "utf-8").replaceAll("\\+", "%20");
            Cookie cookie = new Cookie(AUTHORIZATION_HEADER, cookieValue);
            cookie.setPath("/");
            cookie.setMaxAge(30 * 60);
            res.addCookie(cookie);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e.getMessage());
        }
    }
}
