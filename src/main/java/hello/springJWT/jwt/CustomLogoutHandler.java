package hello.springJWT.jwt;

import hello.springJWT.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomLogoutHandler implements LogoutHandler {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refresh".equals(cookie.getName())) {
                    refresh = cookie.getValue();
                }
            }
        }

        if (refresh != null) {
            try {
                if (!jwtUtil.isExpired(refresh) && "refresh".equals(jwtUtil.getCategory(refresh))) {
                    refreshRepository.deleteByRefreshToken(refresh);
                }
            } catch (ExpiredJwtException e) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                return;
            }
        }
    }
}
