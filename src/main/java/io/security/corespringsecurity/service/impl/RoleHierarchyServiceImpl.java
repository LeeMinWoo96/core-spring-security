package io.security.corespringsecurity.service.impl;

import io.security.corespringsecurity.domain.entity.Rolehierarchy;
import io.security.corespringsecurity.repository.RoleHierarchyRepository;
import io.security.corespringsecurity.service.RoleHierarchyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Iterator;
import java.util.List;

@Service
public class RoleHierarchyServiceImpl implements RoleHierarchyService {

    @Autowired
    private RoleHierarchyRepository roleHierarchyRepository;

    @Override
    @Transactional
    public String findAllHierarchy() {
        List<Rolehierarchy> roleHierarchy = roleHierarchyRepository.findAll();
        Iterator<Rolehierarchy> iterator = roleHierarchy.iterator();
        StringBuilder concatedRoles = new StringBuilder();

        while (iterator.hasNext()){
            Rolehierarchy next = iterator.next();
            if(next.getParentName() != null){
                concatedRoles.append(next.getParentName().getChildName());
                concatedRoles.append(" > ");
                concatedRoles.append(next.getChildName());
                concatedRoles.append("\n");
            }

        }

        return concatedRoles.toString() ;
    }
}
