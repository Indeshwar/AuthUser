package com.web.student_register.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.*;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Entity
public class Role {
    @Id
    @GeneratedValue(strategy= GenerationType.AUTO )
    private Long roleId;
    private String roleName;

    public Role(String roleName){
        this.roleName = roleName;
    }

//    @JsonBackReference
//    @ManyToMany(mappedBy="roles")
//    private Collection<User> users;
//
//
//    @JsonManagedReference
//    @ManyToMany(fetch=FetchType.EAGER)
//    @JoinTable(
//            name="role_permission",
//            joinColumns=@JoinColumn(name ="role_id", referencedColumnName="roleId"),
//            inverseJoinColumns = @JoinColumn(name= "permission_id", referencedColumnName= "permissionId")
//    )
//    private Set<Permission> permissions;

}
