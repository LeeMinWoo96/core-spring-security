package io.security.corespringsecurity.domain.dto;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AccountDto {
    private String id;
    private String username;
    private String email;
    private int age;
    private String password;
    private List<String> roles;
}
