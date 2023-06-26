# Spring security con JWT
Proyecto spring boot usando spring security

## Configuración SecurityConfiguration
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

    http.csrf(x -> x.disable());

    // setting stateless session, because we choose to implement Rest API
    http.sessionManagement(x -> x.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    http.authorizeRequests(x -> x
    .requestMatchers("/").permitAll()
    .requestMatchers("/api/v1/usuarios/autenticar").permitAll()
    .requestMatchers("/api/v1/usuarios/listar").hasAuthority(Constante.ROL_ADMIN)
    .requestMatchers("/api/v1/usuarios/registrar").hasAuthority(Constante.ROL_ADMIN)
    .requestMatchers("/api/v1/usuarios/validar").hasAuthority(Constante.ROL_USER)
    .anyRequest().authenticated());

    // setting custom access denied handler for not authorized request
    http.exceptionHandling(x->x.accessDeniedHandler(new CustomAccessDeniedHandler()));

    // setting custom entry point for unauthenticated request
    http.exceptionHandling(x->x.authenticationEntryPoint(new CustomAuthenticationEntryPoint()));

    http.addFilterBefore(new JTokenFilter(jTokenProvider), UsernamePasswordAuthenticationFilter.class);

    return http.build();
}
```
## Spring Security: Exception Handling

![Exception Handling](https://github.com/eleonv/security-rol-back/blob/main/raw/AccessDeniedHandling.png)


Las excepciones personalizadas se lanzará si:
+ Si el usuario no está autenticado, entonces, se invocará a _CustomAuthenticationEntryPoint_ que hereda de _AuthenticationEntryPoint_.
+ Si el usuario no está autorizado para ver un recurso determinado, entonces, se invocará a _CustomAccessDeniedHandler_ que hereda de _AccessDeniedHandler_.

## Usuarios demo

| Usuario           | Password | Rol       |
| ----------------- |----------|-----------|
| edwin             | edwin    | ROL_ADMIN |
| david             | david    | ROL_ADMIN |
| usuario3          | usuario3 | ROL_USER  |
| usuario4          | usuario4 | ROL_USER  |

## Acknowledgements
- [https://github.com/murraco/spring-boot-jwt](https://github.com/murraco/spring-boot-jwt/blob/master/src/main/java/murraco/security/WebSecurityConfig.java)

## Authors
- [@eleonv](https://github.com/eleonv)

