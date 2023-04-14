package io.security.corespringsecurity.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.context.annotation.Bean;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "ROLE_HIERARCHY")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString(exclude = {"parentName","roleHierarchy"})
public class Rolehierarchy implements Serializable {

    @Id
    @GeneratedValue
    private long id;

    @Column(name = "child_name")
    private String childName;

    @ManyToOne(cascade = {CascadeType.ALL}, fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_name", referencedColumnName = "child_name")
    private Rolehierarchy parentName;

    @OneToMany(mappedBy = "parentName", cascade = {CascadeType.ALL})
    private Set<Rolehierarchy> rolehierarchy = new HashSet<Rolehierarchy>();

}
