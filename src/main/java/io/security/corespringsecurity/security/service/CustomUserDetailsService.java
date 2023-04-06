package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;


//UserDetailsService 란?
//Spring Security에서 유저의 정보를 가져오는 인터페이스이다.
//Spring Security에서 유저의 정보를 불러오기 위해서 구현해야하는 인터페이스로 기본 오버라이드 메서드는 아래와 같다.

@Service("UserDetailsService")
@Transactional
public class CustomUserDetailsService implements UserDetailsService {


    private final UserRepository userRepository;

    @Autowired
    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }



//    Spring Security에서 loginId를 넘겨줄 것이고 loadUserByUsername 에서 해당 값으로 DB를 조회 후 저장되어 있는 유저 정보를 가져온다.
//    그 후에 원하는 형태로 CustomUserDetails를 세팅해준 후 리턴해주면 Spring Security에서는 해당 유저의 정보를 조회할 때에는 CustomUserDetails에 세팅된 값으로 조회를 한 후 로직을 처리해준다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(username);
        if (account == null) {
            if (userRepository.countByUsername(username) == 0) {
                throw new UsernameNotFoundException("No user found with username: " + username);
            }
        }
        assert account != null;
        List<GrantedAuthority> collect = account.getUserRoles()
                .stream()
                .map(Role::getRoleName)
                .collect(Collectors.toSet())
                .stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        //List<GrantedAuthority> collect = userRoles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return new AccountContext(account, collect);
    }
}
