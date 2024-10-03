package com.web.student_register.repository;

import com.web.student_register.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRePo extends JpaRepository<Role, Long> {
    Role getByRoleName(String roleName);
}
