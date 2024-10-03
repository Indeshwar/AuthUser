package com.web.student_register.repository;

import com.web.student_register.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepo extends JpaRepository<User, Long> {
    User getByUserName(String username);
}
