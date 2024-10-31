package com.example.api_user.controller;

// Importações necessárias para manipulação de autenticação e JWT (Json Web Token)
import ch.qos.logback.core.net.SMTPAppenderBase;
import com.example.api_user.dto.LoginDTO;
import com.example.api_user.model.User;
import com.example.api_user.security.JwtTokenProvider;
import com.example.api_user.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    // Dependências injetadas por meio do construtor
    private final AuthenticationManager authenticationManager;

    // O JwtTokenProvider é responsável por gerar tokens JWT para os usuários autenticados.
    private final JwtTokenProvider jwtTokenProvider;

    // UserDetailsService é uma interface do Spring Security que fornece a funcionalidade para carregar detalhes de usuários.
    private final UserDetailsService userDetailsService;

    // O UserService é usado para buscar usuários por ID.
    private final UserService userService;

    // Construtor que recebe as dependências como parâmetros. Essas dependências são injetadas pelo Spring.
    public AuthController(
            AuthenticationManager authenticationManager,
            JwtTokenProvider jwtTokenProvider,
            UserDetailsService userDetailsService,
            UserService userService) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.userDetailsService = userDetailsService;
        this.userService = userService;
    }

    // Anotação @PostMapping("/login"):
    @PostMapping("/login")
    public String login(@RequestBody LoginDTO loginDTO) {
        try {
            // O AuthenticationManager realiza a autenticação baseada no nome de usuário e senha.
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword())
            );

            UserDetails user = (UserDetails) authentication.getPrincipal();
            return jwtTokenProvider.generateToken(user);

        } catch (AuthenticationException error) {
            throw new RuntimeException("Invalid Credentials");
        }
    }

    // Novo método para login com base no ID do usuário
    @GetMapping("/login/{id}")
    public Map<String, String> loginById(@PathVariable int id) {
        String token = jwtTokenProvider.generateTokenById(id);

        Map<String, String> response = new HashMap<>();
        response.put("token", token);
        return response;
    }
}
