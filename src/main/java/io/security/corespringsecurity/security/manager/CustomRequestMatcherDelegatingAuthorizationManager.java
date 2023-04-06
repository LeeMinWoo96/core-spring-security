package io.security.corespringsecurity.security.manager;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.util.Assert;

import java.util.*;
import java.util.function.Supplier;

public class CustomRequestMatcherDelegatingAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
    private final LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>();
    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        Authentication a = authentication.get(); // 이걸 살펴보았다.

        HttpServletRequest request =  object.getRequest();

        requestMap.put(new AntPathRequestMatcher("/mypage"), List.of(new SecurityConfig("ROLE_USER")));
//        AuthorizationDecision authorizationDecision = new AuthorizationDecision(true);
//        return authorizationDecision;


        if(requestMap != null) {
            for(Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()) {
                RequestMatcher matcher = entry.getKey();
                if(matcher.matches(request)) {  //사용자 요청정보와 우리가 갖고있는 요청url 정보가 일치하면
                    return  new AuthorizationDecision(true); // 인증시킨다.
                }
            }
        }
        return new AuthorizationDecision(false);
    }
}