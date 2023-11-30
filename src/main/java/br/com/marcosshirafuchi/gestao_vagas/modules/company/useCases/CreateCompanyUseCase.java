package br.com.marcosshirafuchi.gestao_vagas.modules.company.useCases;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import br.com.marcosshirafuchi.gestao_vagas.exceptions.UserFoundException;
import br.com.marcosshirafuchi.gestao_vagas.modules.company.entities.CompanyEntity;
import br.com.marcosshirafuchi.gestao_vagas.modules.company.repositories.CompanyRepository;

//Regra de negócio
@Service
public class CreateCompanyUseCase {
    //Faz a injeção de independencia
    @Autowired
    private CompanyRepository companyRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public CompanyEntity execute(CompanyEntity companyEntity){
        //Verifica se tem uma empresa cadastrada
        this.companyRepository.findByUsernameOrEmail(companyEntity.getUsername(),companyEntity.getEmail())
        .ifPresent((user)->{
            throw new UserFoundException();
        });

        var password = passwordEncoder.encode(companyEntity.getPassword());
        companyEntity.setPassword(password);
         return this.companyRepository.save(companyEntity);
    }
}
