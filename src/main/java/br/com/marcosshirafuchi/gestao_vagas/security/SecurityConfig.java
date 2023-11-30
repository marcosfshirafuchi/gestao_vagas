package br.com.marcosshirafuchi.gestao_vagas.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

//Vai dizer para o spring que é uma classe de configuração para gerenciar
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private SecurityFilter securityFilter;

    @Autowired
    private SecurityCandidateFilter securityCandidateFilter;


    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http.csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> {
                //Rotas livre de autenticação
                auth.requestMatchers("/candidate/").permitAll()
                .requestMatchers("/company/").permitAll()
                .requestMatchers("/company/auth").permitAll()
                .requestMatchers("/candidate/auth").permitAll();
                //Outras rotas precisam de autenticação
                auth.anyRequest().authenticated();
            })
            .addFilterBefore(securityCandidateFilter,BasicAuthenticationFilter.class)
            .addFilterBefore(securityFilter,BasicAuthenticationFilter.class);
            
        ;
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
	    return new BCryptPasswordEncoder();
    }
}
