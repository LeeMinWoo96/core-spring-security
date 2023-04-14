package io.security.corespringsecurity.repository;

import io.security.corespringsecurity.domain.entity.Rolehierarchy;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleHierarchyRepository extends JpaRepository<Rolehierarchy, Long> {
    Rolehierarchy findByChildName(String name);
}
