package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.AccessIpRepository;
import io.security.corespringsecurity.repository.ResourcesRepository;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;


public class SecurityResourceService {

    private ResourcesRepository resourcesRepository;

    private AccessIpRepository accessIpRepository;

//    public SecurityResourceService(ResourcesRepository resourcesRepository) {
//        this.resourcesRepository = resourcesRepository;
//    }
//    public SecurityResourceService(AccessIpRepository accessIpRepository) {
//        this.accessIpRepository = accessIpRepository;
//    }

    public SecurityResourceService(ResourcesRepository resourcesRepository, AccessIpRepository accessIpRepository) {
        this.resourcesRepository = resourcesRepository;
        this.accessIpRepository = accessIpRepository;
    }

//    public void setResourcesRepository(ResourcesRepository resourcesRepository) {
//        this.resourcesRepository = resourcesRepository;
//    }

    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {
        LinkedHashMap<RequestMatcher,List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> allResources = resourcesRepository.findAllResources();
        allResources.forEach(resources -> {
            List<ConfigAttribute> configAttributeList = new ArrayList<>();
            resources.getRoleSet().forEach(role -> { // 권한 정보 뽑아서
                configAttributeList.add(new SecurityConfig(role.getRoleName())); // 리스트로 만들고
                result.put(new AntPathRequestMatcher(resources.getResourceName()), configAttributeList); // 매핑에 넣어줌 , 포문 밖에 있어야하는거 아닌가
            });
        });

        return result;
    }

    public List<String> getAccessIpList() {
        return accessIpRepository.findAll().stream().map(accessIp -> accessIp.getIpAddress()).collect(Collectors.toList());
    }
}
