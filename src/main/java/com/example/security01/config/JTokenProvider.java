package com.example.security01.config;

import com.example.security01.InitCommandLineRunner;
import com.example.security01.entity.JPAToken;
import com.example.security01.util.Base64;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class JTokenProvider {

    @Autowired
    private UserProvider userProvider;

    public JTokenProvider() {
    }

    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public boolean validateToken(String token) {

        List<JPAToken> list = InitCommandLineRunner.listTokens;

        JPAToken appToken = list.stream()
                .filter(x -> token.equals(x.getValor()))
                .findFirst()
                .orElse(null);

        if (appToken == null) {
            throw new CustomException("Invalid token", HttpStatus.UNAUTHORIZED);
        }

        return true;
    }

    public Authentication getAuthentication(String token) {

        UserDetails userDetails = userProvider.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public String getUsername(String token) {
        return Base64.base64ToString(token);
    }
}
