package io.security.corespringsecurity.controller.login;

import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.security.service.AccountContext;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;

@Controller
public class LoginController {
    @RequestMapping(value = {"/login", "/api/login"})
    public String login(@RequestParam(value = "error", required = false) String error
    , @RequestParam(value = "exception", required = false) String exception, Model model)
    {
        model.addAttribute("error", error);
        model.addAttribute("exception", exception);
        return "user/login/login";
    }

    @GetMapping("/logout") // Security Context 의 logout은 두개의 파라미터를 받음
    public String logout(HttpServletRequest request, HttpServletResponse response){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        인증 개게가 있다면 LogoutHandler 통해 로그아웃
        if(authentication != null){
            new SecurityContextLogoutHandler().logout(request,response,authentication);
        }
        return "redirect:/login";
    }
    @GetMapping(value = {"/denied","/api/denied"})
    public String denied(@RequestParam(value = "exception",required = false) String exception
    , Principal principal, Model model){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        Account account = (Account) authentication.getPrincipal();
        Account account = null;
        if (principal instanceof UsernamePasswordAuthenticationToken){
//            System.out.println(principal);
            //어쩔때 account context 고 어쩔땐 account 고 그걸 모르겠네
            try {
                AccountContext accountContext = (AccountContext) authentication.getPrincipal();
                account = accountContext.getAccount();
            }catch (ClassCastException e){
                account = (Account) authentication.getPrincipal();
            }

        }
        else if(principal instanceof AjaxAuthenticationToken){
            account = (Account) ((AjaxAuthenticationToken) principal).getPrincipal();
        }

        model.addAttribute("username",account.getUsername());
        model.addAttribute("exception",exception);

        return "user/login/denied";
    }
}
