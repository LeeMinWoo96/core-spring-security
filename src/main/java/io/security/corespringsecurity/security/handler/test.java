//package io.security.corespringsecurity.security.handler;
//
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.web.DefaultRedirectStrategy;
//import org.springframework.security.web.RedirectStrategy;
//import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
//import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
//import org.springframework.security.web.savedrequest.RequestCache;
//import org.springframework.security.web.savedrequest.SavedRequest;
//import org.springframework.stereotype.Component;
//
//import java.io.IOException;
//
//@Component
//public class test extends SimpleUrlAuthenticationSuccessHandler {
//    private RequestCache requestCache = new HttpSessionRequestCache();
//    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//        setDefaultTargetUrl("/");
//        SavedRequest saveRequest = requestCache.getRequest(request,response);//가려고 했던 경로
//        if (saveRequest != null){
//            String targetUrl = saveRequest.getRedirectUrl();
//            redirectStrategy.sendRedirect(request,response,targetUrl);
//        }
//        else {
////            set한 기본 url 로 이동
//            redirectStrategy.sendRedirect(request,response,getDefaultTargetUrl());
//        }
//        super.onAuthenticationSuccess(request, response, authentication);
//    }
//}
