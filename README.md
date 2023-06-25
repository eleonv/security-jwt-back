# Spring security basic
Proyecto spring boot usando spring security

## Configuracion SecurityConfiguration
```java
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
```

## Acknowledgements
 - [https://github.com/murraco/spring-boot-jwt](https://github.com/murraco/spring-boot-jwt/blob/master/src/main/java/murraco/security/WebSecurityConfig.java)

## Authors
- [@eleonv](https://github.com/eleonv)

