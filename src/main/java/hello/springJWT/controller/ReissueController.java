package hello.springJWT.controller;

import hello.springJWT.common.Role;
import hello.springJWT.domain.Refresh;
import hello.springJWT.jwt.JWTUtil;
import hello.springJWT.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.Objects;

@RestController
@RequiredArgsConstructor
public class ReissueController {

    private final RefreshRepository refreshRepository;
    private final JWTUtil jwtUtil;

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();

        String refresh = null;

        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
            }
        }

        if (refresh == null) {
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

        // 만료일 체크
        try {
            jwtUtil.isExpired(refresh);

        } catch (ExpiredJwtException e) {
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        // 리프 레시 토큰 확인
        String category = jwtUtil.getCategory(refresh);

        if (!category.equals("refresh")) {
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        Boolean isExists = refreshRepository.existsByRefreshToken(refresh);

        if (!isExists) {
            return new ResponseEntity<>("refresh token not found", HttpStatus.BAD_REQUEST);
        }

        String username = jwtUtil.getUsername(refresh);
        Role role = Role.fromString(jwtUtil.getRole(refresh));

        String newAccess = jwtUtil.createJwt("access", username, role, 600000L);
        String newRefresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        refreshRepository.deleteByRefreshToken(refresh);

        refreshRepository.save(Refresh.createRefresh(username,
                newRefresh,
                new Date(System.currentTimeMillis() + 86400000L).toString()));

        response.addCookie(createCookie("access", newAccess));
        response.addCookie(createCookie("refresh", newRefresh));


        return new ResponseEntity<>(HttpStatus.OK);
    }

    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);

        if (Objects.equals(key, "access")) {
            cookie.setMaxAge(10 * 60);
            cookie.setHttpOnly(true);
        }

        else if (Objects.equals(key, "refresh")) {
            cookie.setMaxAge(24 * 60 * 60);
            cookie.setHttpOnly(true);
        }

        return cookie;
    }
}
