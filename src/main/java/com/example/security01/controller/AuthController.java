package com.example.security01.controller;

import com.example.security01.InitCommandLineRunner;
import com.example.security01.config.CustomException;
import com.example.security01.entity.JPAToken;
import com.example.security01.entity.JPAUsuario;
import com.example.security01.entity.RequestUsuario;
import com.example.security01.entity.ResponseApi;
import com.example.security01.util.Base64;
import com.example.security01.util.Constante;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin("http://localhost:4200")
@RestController
@RequestMapping("/api/v1/usuarios/")
public class AuthController {
    @PostMapping(value = "autenticar", produces = "application/json")
    public ResponseEntity<?> listar(@RequestBody RequestUsuario requestUsuario, HttpServletRequest request) {

        String username = requestUsuario.getUsername();
        String password = requestUsuario.getPassword();

        ResponseApi responseAppBean = new ResponseApi();
        try {
            List<JPAUsuario> list = InitCommandLineRunner.listUsuarios;

            JPAUsuario appUser = list.stream().filter(x -> username.equals(x.getUsername())).findFirst().orElse(null);
            if (appUser == null) {
                throw new UsernameNotFoundException("User '" + username + "' not found");
            }

            if(!password.equals(appUser.getPassword())) {
                throw new BadCredentialsException("El usuario no se encuentra registrado en el sistema");
            }

            String userEncode = Base64.stringToBase64(username);

            JPAToken token = new JPAToken();
            token.setValor(userEncode);
            InitCommandLineRunner.listTokens.add(token);

            responseAppBean.setStatus(Constante.RESPONSE_OK);
            responseAppBean.setMessage("Usuario autenticado: " + username);
            responseAppBean.setData(userEncode);
            return new ResponseEntity<>(responseAppBean, HttpStatus.OK);
        } catch (BadCredentialsException e) {
            responseAppBean.setStatus(Constante.RESPONSE_ERROR);
            responseAppBean.setMessage("No autorizado");
            return new ResponseEntity<>(responseAppBean, HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            responseAppBean.setStatus(Constante.RESPONSE_ERROR);
            return new ResponseEntity<>(responseAppBean, HttpStatus.ACCEPTED);
        }
    }
}
