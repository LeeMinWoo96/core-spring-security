package io.security.corespringsecurity.security.provider;

import io.security.corespringsecurity.security.common.FormWebAuthenticationDetails;
import io.security.corespringsecurity.security.service.AccountContext;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class AjaxAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private PasswordEncoder passwordEncoder;


    //    로그인 시 검증
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();


        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);//userdetail 타입의 객체 얻어옴

//        사용자가 입력한 패스워드와, accontContext 에 있는 패스워드(DB) 에 저정돠있는 값 비교
//        {bcrypt}$2a$10$osxkLDiGxVH2Yrc0QBtjw.CJEr1V23l2zEkf4q573OTNgopvMXIFi
        if(! passwordEncoder.matches(password,accountContext.getAccount().getPassword())){
            throw new BadCredentialsException("BadCredentialsException");
        }

//        인증 성공시 인증 토큰객체 생성
        AjaxAuthenticationToken authenticationToken = new AjaxAuthenticationToken(accountContext.getAccount(),null,accountContext.getAuthorities());
//        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(accountContext.getAccount(),null,accountContext.getAuthorities());




        System.out.println("DEBUG " + SecurityContextHolder.getContext());
        return authenticationToken;
    }

    // token 타입에 따라 이 provider 가 언제 동작할지를 명시 함
//    즉 UsernamePasswordAuthenticationToken 의 경우에만 이 CustomProvider 가 동작하는 것
    @Override
    public boolean supports(Class<?> authentication) {
        return AjaxAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
