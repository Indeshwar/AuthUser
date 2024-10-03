package com.web.student_register;

import com.web.student_register.entity.Role;
import com.web.student_register.entity.User;
import com.web.student_register.repository.RoleRePo;
import com.web.student_register.repository.UserRepo;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.annotation.Rollback;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Rollback(false)
public class UserRepositoryTest {
    @Autowired
    private UserRepo userRepo;
    @Autowired
    private RoleRePo roleRepo;
    @Autowired
    private TestEntityManager entityManager;

//    @Test
//    public void testCreateUser(){
//        User user = new User();
//        user.setUserName("ram");
//        user.setPassword("ram");
//
//        User savedUser = userRepo.save(user);
//        User existingUser = entityManager.find(User.class, savedUser.getId());
//        assertThat(user.getUserName()).isEqualTo(existingUser.getUserName());
//
//    }

    @Test
    public void testAddRoleToNewUser(){
        Role role = roleRepo.getByRoleName("User");
        User user = new User();
        user.setUserName("gopal");
        user.setPassword("gopal");
        user.addRole(role);

        User savedUser = userRepo.save(user);
        assertThat(savedUser.getRoles().size()).isEqualTo(1);
    }
}
