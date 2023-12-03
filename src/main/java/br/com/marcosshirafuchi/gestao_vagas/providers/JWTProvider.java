package br.com.marcosshirafuchi.gestao_vagas.providers;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

@Service
public class JWTProvider {
    @Value("security.token.secret")
    private String secretkey;

    public DecodedJWT validateToken(String token){
        token = token.replace("Bearer ","");
        Algorithm algorithm = Algorithm.HMAC256(secretkey);
        
        try {
            var tokenDecoded = JWT.require(algorithm)
        .build()
        .verify(token);
        return tokenDecoded;
        } catch (JWTVerificationException e) {
            //Retorna a mensagem completa
            e.printStackTrace();
            return null;
        }
    }
}
