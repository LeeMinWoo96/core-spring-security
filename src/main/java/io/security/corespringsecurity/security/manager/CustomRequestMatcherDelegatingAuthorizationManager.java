package io.security.corespringsecurity.security.manager;

import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import io.security.corespringsecurity.service.SecurityResourceService;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.log.LogMessage;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.util.Assert;


import java.util.*;
import java.util.function.Supplier;

public class CustomRequestMatcherDelegatingAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
//    private final LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>();
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap;

    private SecurityResourceService securityResourceService;

//    @Autowired
//    private UrlFilterInvocationSecurityMetadataSource securityMetadataSource;
//    accessmanager deprecate 되구 나온거 vote 방식 사라짐
    private AuthorizationManager  AuthorizationManager ;

    private List<GrantedAuthority> authorities;
    private RoleHierarchy roleHierarchy = new NullRoleHierarchy();


    public CustomRequestMatcherDelegatingAuthorizationManager(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourceMap) {
        this.requestMap = resourceMap;
    }

    private boolean isAuthorized(Authentication authentication) {
        Set<String> authorities = AuthorityUtils.authorityListToSet(this.authorities);
        for (GrantedAuthority grantedAuthority : getGrantedAuthorities(authentication)) {
            if (authorities.contains(grantedAuthority.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
        Assert.notNull(roleHierarchy, "roleHierarchy cannot be null");
        this.roleHierarchy = roleHierarchy;
    }

    private Collection<? extends GrantedAuthority> getGrantedAuthorities(Authentication authentication) {
        return this.roleHierarchy.getReachableGrantedAuthorities(authentication.getAuthorities());
    }

    private boolean isGranted(Authentication authentication) {
        return authentication != null && authentication.isAuthenticated() && isAuthorized(authentication);
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        Authentication a = authentication.get();
        // Voter
        WebAuthenticationDetails details = (WebAuthenticationDetails) a.getDetails();
        String remoteAddress = details.getRemoteAddress();
        List<String> accessIpList = securityResourceService.getAccessIpList();

        boolean isRemoteAddressAllowed = false;
        for(String ipAddress: accessIpList){
            if(remoteAddress.equals(ipAddress)){
                isRemoteAddressAllowed = true;
                break;
            }
        }

        if(!isRemoteAddressAllowed){
            return  new AuthorizationDecision(false);
        }



        Set<Role> userRoles = null;

        Collection<? extends GrantedAuthority> grantedAuthorities = getGrantedAuthorities(a);
        System.out.println(grantedAuthorities);

        if (a.getClass() == AnonymousAuthenticationToken.class){
            userRoles = new HashSet<>();
        }
        else {
            Account account = (Account) a.getPrincipal();
            userRoles = account.getUserRoles();
        }

        HttpServletRequest request =  object.getRequest();


//        requestMap.put(new AntPathRequestMatcher("/mypage"), List.of(new SecurityConfig("ROLE_ADMIN")));



        //        // role hierarchy 미적용 한거
        //        Arrays.asList(userRoles);

//        List<SecurityConfig> roleList = new ArrayList<>();
//
//        for(Role role : userRoles){
//            roleList.add(new SecurityConfig(role.getRoleName()));
//        }

        List<SecurityConfig> roleList = new ArrayList<>();

        for(GrantedAuthority grantedAuthoriy : grantedAuthorities){
            roleList.add(new SecurityConfig(grantedAuthoriy.getAuthority()));
        }

        if(requestMap != null) {
            for(Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()) {
                RequestMatcher matcher = entry.getKey();
                if(matcher.matches(request)) {  //사용자 요청정보와 우리가 갖고있는 요청url 정보가 일치하면 + 저것도 권한체크

//                    if(roleList.containsAll(entry.getValue())){
//                        return  new AuthorizationDecision(true);
//                    }
//                    return  new AuthorizationDecision(false); // 인증시킨다.

                    //       role hierarchy 적용
                    if(roleList.containsAll(entry.getValue())){
                        return  new AuthorizationDecision(true); // 인증
                    }
                    return  new AuthorizationDecision(false); // 거부.

                }
            }
        }
        return new AuthorizationDecision(false);
    }

    public void setSecurityResourceService(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }
}