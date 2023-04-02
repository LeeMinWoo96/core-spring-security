package io.security.corespringsecurity.security.common;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@Component
// Custom detail 을 쓰기 위해서 작성 // 빈으로 등록 후 config 에 등록
public class FormAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {
    @Override
    public WebAuthenticationDetails buildDetails(HttpServletRequest context) { // 필터 에서
//        보내면 request 값을 details 에 저장
        return new FormWebAuthenticationDetails(context);
    }
}
