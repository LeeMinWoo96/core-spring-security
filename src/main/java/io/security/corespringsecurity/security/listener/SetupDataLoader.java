package io.security.corespringsecurity.security.listener;

import io.security.corespringsecurity.domain.entity.*;
import io.security.corespringsecurity.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {
    private boolean alreadySetup = false;

    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private ResourcesRepository resourcesRepository;
    private PasswordEncoder passwordEncoder;

    private RoleHierarchyRepository roleHierarchyRepository;
    private AccessIpRepository accessIpRepository;

    @Autowired
    private void setSetupDataLoader(UserRepository userRepository, RoleRepository roleRepository, ResourcesRepository resourcesRepository,RoleHierarchyRepository roleHierarchyRepository, PasswordEncoder passwordEncoder, AccessIpRepository accessIpRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.resourcesRepository = resourcesRepository;
        this.roleHierarchyRepository = roleHierarchyRepository;
        this.passwordEncoder = passwordEncoder;
        this.accessIpRepository = accessIpRepository;
    }

    private static final AtomicInteger count = new AtomicInteger(0);

    @Override
    @Transactional
    public void onApplicationEvent(final ContextRefreshedEvent event) {

        if (alreadySetup) {
            return;
        }

        setupSecurityResources();
        setupAccessIpData();

        alreadySetup = true;
    }



    private void setupSecurityResources() {
        Set<Role> roles = new HashSet<>();
        Role adminRole = createRoleIfNotFound("ROLE_ADMIN", "관리자");
        roles.add(adminRole);
        createResourceIfNotFound("/admin/**", "", roles, "url");
        Account account = createUserIfNotFound("admin", "1111", "admin@gmail.com", 10,  roles);

        createRoleHierarchyIfNotFound("ROLE_MANAGER","ROLE_ADMIN");

        Set<Role> roles1 = new HashSet<>();
//
        Role managerRole = createRoleIfNotFound("ROLE_MANAGER", "매니저");
        roles1.add(managerRole);
        createResourceIfNotFound("/message/**", "", roles1, "url");
//        createResourceIfNotFound("io.security.corespringsecurity.aopsecurity.method.AopMethodService.methodTest", "", roles1, "method");
//        createResourceIfNotFound("io.security.corespringsecurity.aopsecurity.method.AopMethodService.innerCallMethodTest", "", roles1, "method");
//        createResourceIfNotFound("execution(* io.security.corespringsecurity.aopsecurity.pointcut.*Service.*(..))", "", roles1, "pointcut");
        createUserIfNotFound("manager", "1111", "manager@gmail.com", 20, roles1);
//
//        Set<Role> roles3 = new HashSet<>();
//
//        Role childRole1 = createRoleIfNotFound("ROLE_USER", "회원");
//        roles3.add(childRole1);
//        createResourceIfNotFound("/users/**", "", roles3, "url");
//        createUserIfNotFound("user", "pass", "user@gmail.com", 30, roles3);

    }

    @Transactional
    public Role createRoleIfNotFound(String roleName, String roleDesc) {

        Role role = roleRepository.findByRoleName(roleName);

        if (role == null) {
            role = Role.builder()
                    .roleName(roleName)
                    .roleDesc(roleDesc)
                    .build();
        }
        return roleRepository.save(role);
    }

    @Transactional
    public Account createUserIfNotFound(String userName, String password, String email, int age, Set<Role> roleSet) {

        Account account = userRepository.findByUsername(userName);

        if (account == null) {
            account = Account.builder()
                    .username(userName)
                    .email(email)
                    .age(age)
                    .password(passwordEncoder.encode(password))
                    .userRoles(roleSet)
                    .build();
        }
        return userRepository.save(account);
    }

    @Transactional
    public Resources createResourceIfNotFound(String resourceName, String httpMethod, Set<Role> roleSet, String resourceType) {
        Resources resources = resourcesRepository.findByResourceNameAndHttpMethod(resourceName, httpMethod);

        if (resources == null) {
            resources = Resources.builder()
                    .resourceName(resourceName)
                    .roleSet(roleSet)
                    .httpMethod(httpMethod)
                    .resourceType(resourceType)
                    .orderNum(count.incrementAndGet())
                    .build();
        }
        return resourcesRepository.save(resources);
    }

    @Transactional
    public Rolehierarchy createRoleHierarchyIfNotFound(String childRole, String parentRole){
        Rolehierarchy byChildName = this.roleHierarchyRepository.findByChildName(childRole);
        Role byRoleName = roleRepository.findByRoleName(parentRole);

        Rolehierarchy rolehierarchy = new Rolehierarchy();
        rolehierarchy.setChildName("ROLE_ADMIN");


        if (byChildName == null) {
            byChildName = Rolehierarchy.builder()
                    .childName(childRole)
                    .parentName(rolehierarchy)
                    .build();
        }
        return roleHierarchyRepository.save(byChildName);
    }

    private void setupAccessIpData() {
        AccessIp byIpAddress = accessIpRepository.findByIpAddress("0:0:0:0:0:0:0:1");
        if (byIpAddress == null) {
            AccessIp accessIp = AccessIp.builder()
                    .ipAddress("0:0:0:0:0:0:0:1")
                    .build();
            accessIpRepository.save(accessIp);
        }
    }
}
