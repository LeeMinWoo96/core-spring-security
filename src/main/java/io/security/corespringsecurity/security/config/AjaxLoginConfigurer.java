package io.security.corespringsecurity.security.config;

import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.core.parameters.P;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

// 그냥 핸들러 등록해서 쓸 수도 있지만
// 이렇게 DSL 로 설정해서 규격화해서 쓸수도 있음

/*
<H extends **<H>>은 제네릭 타입 매개변수를 사용하여 클래스에서 상속할 수 있는 타입의 범위를 제한하는 방법 중 하나입니다.

여기서 H는 제네릭 타입 매개변수 이름으로, 일반적으로 "Type Parameter"로 이해됩니다. 이 매개변수는 클래스에서 사용할 타입을 나타내며, 상위 클래스에서 선언된 제네릭 타입 매개변수를 상속받아 하위 클래스에서 사용하는 경우가 많습니다.

<H extends **<H>>와 같이 표현된 제네릭 타입 매개변수는 H 타입이 H 클래스 또는 H 클래스의 하위 클래스임을 나타냅니다. 이렇게 하면 상위 클래스에서 정의한 제네릭 타입 매개변수의 범위를 하위 클래스에서 제한할 수 있습니다.

예를 들어, <H extends Comparable<H>>는 Comparable 인터페이스를 구현하는 H 클래스 또는 H 클래스의 하위 클래스만 타입 매개변수로 사용할 수 있다는 것을 의미합니다. 따라서 Comparable 인터페이스를 구현하는 클래스에서만 사용 가능한 메서드를 하위 클래스에서도 사용할 수 있게 됩니다.
 */
public class AjaxLoginConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractAuthenticationFilterConfigurer<H, AjaxLoginConfigurer<H>, AjaxLoginProcessingFilter> {

    private AuthenticationSuccessHandler authenticationSuccessHandler;
    private AuthenticationFailureHandler authenticationFailureHandler;
    private AuthenticationManager authenticationManager;

    public AjaxLoginConfigurer(){
        super(new AjaxLoginProcessingFilter(),null);
    }

    @Override
    public void init(H http) throws Exception {
        super.init(http);
    }

    @Override
    public void configure(H http) throws Exception {
        if(authenticationManager == null){
            authenticationManager = http.getSharedObject(AuthenticationManager.class);
        }

        getAuthenticationFilter().setAuthenticationManager(authenticationManager);
        getAuthenticationFilter().setAuthenticationFailureHandler(authenticationFailureHandler);
        getAuthenticationFilter().setAuthenticationSuccessHandler(authenticationSuccessHandler);


        SessionAuthenticationStrategy sessionAuthenticationStrategy = http.getSharedObject(SessionAuthenticationStrategy.class);

        if(sessionAuthenticationStrategy != null){
            getAuthenticationFilter().setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }

        RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);

        if(rememberMeServices != null){
            getAuthenticationFilter().setRememberMeServices(rememberMeServices);
        }
        http.setSharedObject(AjaxLoginProcessingFilter.class,getAuthenticationFilter());
        http.addFilterBefore(getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

    }
    public AjaxLoginConfigurer<H> successHandlerAjax(AuthenticationSuccessHandler successHandler){
        this.authenticationSuccessHandler =successHandler;
        return this;
    }

    public AjaxLoginConfigurer<H> failureHandlerAjax(AuthenticationFailureHandler failureHandler){
        this.authenticationFailureHandler = failureHandler;
        return this;
    }

    public AjaxLoginConfigurer<H> setAuthenticationManager(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
        return this;
    }

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl){
        return new AntPathRequestMatcher(loginProcessingUrl,"POST");
    }


}
