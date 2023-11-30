package br.com.marcosshirafuchi.gestao_vagas.modules.candidate.useCases;

import java.time.Instant;
import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import br.com.marcosshirafuchi.gestao_vagas.modules.candidate.CandidateRepository;
import br.com.marcosshirafuchi.gestao_vagas.modules.candidate.dto.AuthCandidateRequestDTO;
import br.com.marcosshirafuchi.gestao_vagas.modules.candidate.dto.AuthCandidateResponseDTO;
import jakarta.security.auth.message.AuthException;

@Service
public class AuthCandidateUseCase {

    @Value("security.token.secret.candidate")
    private String secretkey;

    @Autowired
    private CandidateRepository candidateRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public AuthCandidateResponseDTO execute(AuthCandidateRequestDTO authCandidateRequestDTO) throws AuthException{
        var candidate = this.candidateRepository.findByUsername(authCandidateRequestDTO.username())
        .orElseThrow(() ->{
            throw new UsernameNotFoundException("Username/passourd incorrect");
        });

        var passwordMatches = this.passwordEncoder
        .matches(authCandidateRequestDTO.password(), candidate.getPassword());

        if(!passwordMatches){
            throw new AuthException();
        }

        //Passar o token
        Algorithm algorithm = Algorithm.HMAC256(secretkey);
        var expiresIn = Instant.now().plus(java.time.Duration.ofMinutes(10));
        var token = JWT.create()
        .withIssuer("javagas")
        .withSubject(candidate.getId().toString())
        .withClaim("roles", Arrays.asList("candidate"))
        .withExpiresAt(expiresIn)
        .sign(algorithm);

        var authCandidateResponse = AuthCandidateResponseDTO.builder()
        .access_token(token)
        .expire_in(expiresIn.toEpochMilli())
        .build();

        return authCandidateResponse;
    }
}
