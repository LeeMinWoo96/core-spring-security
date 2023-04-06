package io.security.corespringsecurity.security.metadatasource;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.*;

public class UrlFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
//    hashmap 인데 순서정보가 있는게 linkedhashmap
//    요청정보(자원정보)와 권한정보를 매핑한 map 을 구성하는것
//    이 방식 deprecated 됨
    private final LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>();


    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
//        HttpServletRequest request1 = ((FilterInvocation) object).getRequest();
        HttpServletRequest request = ((FilterInvocation) object).getRequest();

//
        requestMap.put(new AntPathRequestMatcher("/mypage"), List.of(new SecurityConfig("ROLE_USER")));

        if(requestMap != null) {
            for(Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()) {
                RequestMatcher matcher = entry.getKey();
                if(matcher.matches(request)) {  //사용자 요청정보와 우리가 갖고있는 요청url 정보가 일치하면
                    return entry.getValue(); // 권한정보를 반환한다.
                }
            }
        }

        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet<>();

        for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()) {
            allAttributes.addAll(entry.getValue());
        }

        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }
}