package com.example.security01.config;

import com.example.security01.util.Constante;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    private final JTokenProvider jTokenProvider;

    public SecurityConfiguration(JTokenProvider jTokenProvider) {
        this.jTokenProvider = jTokenProvider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf(x -> x.disable());
        http.sessionManagement(x -> x.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeRequests(x -> x
                .requestMatchers("/").permitAll()
                .requestMatchers("/api/v1/usuarios/autenticar").permitAll()
                .requestMatchers("/api/v1/usuarios/listar").hasAuthority(Constante.ROL_ADMIN)
                .requestMatchers("/api/v1/usuarios/registrar").hasAuthority(Constante.ROL_ADMIN)
                .requestMatchers("/api/v1/usuarios/validar").hasAuthority(Constante.ROL_USER)
                .anyRequest().authenticated());

        http.exceptionHandling(x->x.authenticationEntryPoint(new ExceptionAuthenticationEntryPoint()));
        http.addFilterBefore(new JTokenFilter(jTokenProvider), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}
