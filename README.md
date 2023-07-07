# Spring security con JWT
Proyecto spring boot 3.1.0 usando spring security y JWT

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

    http.addFilterBefore(new JwtTokenFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);

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

## JSON Web Token (JWT)
Es un estándar abierto (RFC 7519) que define una forma compacta y autónoma de transmitir información de forma segura entre las partes como un objeto JSON. Esta información se puede verificar y confiar porque está firmada digitalmente. Los JWT se pueden firmar usando un secreto (con el algoritmo HMAC) o un par de claves pública/privada usando RSA.

Los tokens web JSON constan de tres partes separadas por puntos (.), que son:
- Header
- Payload
- Signature

JWT tiene la siguiente forma: xxxxx.yyyyy.zzzzz

El siguiente diagrama muestra el funcionamiento de los tokens web JSON:
![Funcionamiento JWT](https://github.com/eleonv/security-jwt-back/blob/main/raw/do-jwt.png)

## Acknowledgements
- [https://github.com/murraco/spring-boot-jwt](https://github.com/murraco/spring-boot-jwt/blob/master/src/main/java/murraco/security/WebSecurityConfig.java)

## Authors
- [@eleonv](https://github.com/eleonv)

