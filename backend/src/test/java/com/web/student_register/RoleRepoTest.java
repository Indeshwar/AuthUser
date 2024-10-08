package com.web.student_register;

import com.web.student_register.entity.Role;
import com.web.student_register.repository.RoleRePo;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.annotation.Rollback;

import java.util.List;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Rollback(false)
public class RoleRepoTest {
    @Autowired
    private RoleRePo roleRepo;

    @Test
    public void createTestRole(){
        System.out.print("This is create test class");
        Role user = new Role("USER");
        Role admin = new Role("ADMIN");
        Role guest = new Role("GUEST");
        roleRepo.saveAll(List.of(user, admin, guest));
        List<Role> listOfRoles = roleRepo.findAll();
        assertThat(listOfRoles.size()).isEqualTo(3);
    }
}
