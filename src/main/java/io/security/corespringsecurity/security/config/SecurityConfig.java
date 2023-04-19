package io.security.corespringsecurity.security.config;

//import io.security.corespringsecurity.security.handler.CustomAuthenticationSuccessHandler;

import io.security.corespringsecurity.security.common.FormAuthenticationDetailsSource;
import io.security.corespringsecurity.security.factory.UrlResourceMapFactoryBean;
import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.security.manager.CustomRequestMatcherDelegatingAuthorizationManager;
import io.security.corespringsecurity.security.provider.CustomAuthenticationProvider;
import io.security.corespringsecurity.service.RoleHierarchyService;
import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.Arrays;

// form 인증방식 설정 클래스
@Configuration
@EnableWebSecurity
@Order(1)
public class SecurityConfig {

//    @Bean
//    public UserDetailsManager user_test() {
//
//        String password = passwordEncoder().encode("1111");
//
//        UserDetails user = User.builder()
//                .username("user")
//                .password(password) // 어떤 유형으로 암호화 했는지 prefix 로 적어줘야함 noop은 암호화를 하지 않겠다는 뜻
//                .roles("USER")
//                .build();
//
//        UserDetails sys = User.builder()
//                .username("manager")
//                .password(password)
//                .roles("MANAGER")
//                .build();
//
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password(password)
//                .roles("ADMIN", "MANAGER", "USER") // admin 이 상위권한인것처럼 다 할당해줘야함 물론 권한 계층에 관한 내용 적용하면 이리 안해도 댐
//                .build();
//
//        return new InMemoryUserDetailsManager( user, sys, admin );
//    }

    private final FormAuthenticationDetailsSource authenticationDetailsSource;

    @Autowired
    // AuthenticationSuccessHandler 이건 authentication 선언체임
    // 즉 저 선언체로 만든 구현체들을 다 머시깽이 할 수 있다 이거야!
    private AuthenticationSuccessHandler customAuthenticationSuccessHandler;

//    AuthenticationSuccessHandler 인터페이스 타입을 사용하는 경우에는 타입 충돌이 발생하지 않도록
//    클래스이름의 변수명을 적어 주셔야 합니다. 즉 변수명을 참고하는듯
//    하나만 있을땐 상관 없는데 동일 인터페이스 사용하는 경우는 변수 기준으로 참조

//    1. 필드명 매칭
//조회된 빈들 중에서 자동주입이 되어야 하는 필드 변수의 이름과 같은 이름의 빈이 있다면 이 빈을 우선적으로 등록한다.
    @Autowired
    private AuthenticationFailureHandler customAuthenticationFailureHandler;

    @Autowired
    private CustomAccessDeniedHandler accessDeniedHandler;

    @Autowired
    private SecurityResourceService securityResourceService;

    @Autowired
    public SecurityConfig(FormAuthenticationDetailsSource authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }


    //   정적 자원은 보안필터 거치지 않고 접근 가능하도록 설정
//    permit all 같은 경우는 보안필터를 걸쳐서 인증을 다 통과해주겠다라는 거여서 보안필터는 거침
//    아래 코드는 보안필터 자체를 걸치지 않느거지
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                .requestMatchers("/favicon.ico", "/resources/**", "/error")
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

//    initializer 에서 쓰려고
    @Bean
    public RoleHierarchyImpl roleHierarchy(){
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        return roleHierarchy;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = authenticationManager2();
        urlResourceMapFactoryBean();

        http.authenticationManager(authenticationManager);
        CustomRequestMatcherDelegatingAuthorizationManager customRequestMatcherDelegatingAuthorizationManager = new CustomRequestMatcherDelegatingAuthorizationManager(urlResourceMapFactoryBean().getObject());
        customRequestMatcherDelegatingAuthorizationManager.setSecurityResourceService(securityResourceService);
        customRequestMatcherDelegatingAuthorizationManager.setRoleHierarchy(roleHierarchy());

        http
                .authorizeHttpRequests(authorize -> {
                    try {
                        authorize
                        .requestMatchers("/", "/users", "/login*", "users/login/**","/login_proc","/denied/**","/logout").permitAll()
        //                .requestMatchers("/mypage").hasRole("USER")
        //                .requestMatchers("/message").hasRole("MANAGER")
        //                .requestMatchers("/config").hasRole("ADMIN")
                        .requestMatchers("/").permitAll()
                        .requestMatchers("/**").access(customRequestMatcherDelegatingAuthorizationManager)
                        .anyRequest()
                        .authenticated()
                        .and();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(authenticationDetailsSource)
                .defaultSuccessUrl("/")
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)
                .permitAll()
                .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler)
                ;

//      프로바이더 안먹네 왜지
//        http.authenticationManager(authenticationManager);




        return http.build();
    }

    private UrlResourceMapFactoryBean urlResourceMapFactoryBean() {
        UrlResourceMapFactoryBean urlResourceMapFactoryBean = new UrlResourceMapFactoryBean();
        urlResourceMapFactoryBean.setSecurityResourceService(securityResourceService);
        return urlResourceMapFactoryBean;
    }

//    @Autowired
//    private UserDetailsService userDetailsService;

//   커스텀 UserDetailService 등록 이라고 생각했는데 이게 없어도 되네 ..?
//    어디서 호출하는거지
//    https://stackoverflow.com/questions/71605941/spring-security-global-authenticationmanager-without-the-websecurityconfigurera
//    돌겠다~

//    @Bean
//    public AuthenticationManager authenticationManager1(AuthenticationConfiguration auth) throws Exception{
//        return auth.getAuthenticationManager();
//    }

//    위 처럼이 아니라 이래해야 ajax 하고 custom 둘다 프로바이더에 등록된다 ~!
//    대충 보면 뭐 같은 manager 에 등록을 해야하는데
//    위 처럼 auth.getAuthenticationManager(); 이렇게만 하면 그냥 각각 다른 manager 객체에 등록된다 이런뜻
//    @Bean
//    public AuthenticationManager authenticationManager2(AuthenticationConfiguration authenticationConfiguration) throws Exception {
//        ProviderManager authenticationManager = (ProviderManager)authenticationConfiguration.getAuthenticationManager();
//        authenticationManager.getProviders().add(customAuthenticationProvider());
//        return authenticationManager;
//    }
//
    @Bean
    public AuthenticationManager authenticationManager2() {
        return new ProviderManager(Arrays.asList(customAuthenticationProvider()));
    }


    //  커스텀 인증 provider 등록 // 그래도 Provider의 support 함수로 어떤
//    인증 절차시 이 provider 가 수행할 것인지를 명시 함
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }


//    이런식으로 bean 으로 구성할 수도 있고
//    아님 bean 으로 선언하고 autowired 로 DI 받을 수도 있음
//    @Bean
//    public AccessDeniedHandler accessDeniedHandler(){
//        CustomAccessDeniedHandler customAccessDeniedHandler = new CustomAccessDeniedHandler();
//        customAccessDeniedHandler.setErrorPage("/denied");
//        return customAccessDeniedHandler;
//    }

    @Bean
    public ProviderManager providerManager() {
        return new ProviderManager(Arrays.asList(customAuthenticationProvider()));
    }

//    @Bean
//    public AuthorizationFilter customAuthorizationFilter(){
////        AuthorizationFilter authorizationFilter = new AuthorizationFilter();
//    }

}
