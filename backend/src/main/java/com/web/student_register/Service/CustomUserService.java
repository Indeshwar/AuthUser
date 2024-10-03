package com.web.student_register.Service;

import com.web.student_register.Dto.UserDto;
import com.web.student_register.config.JWTTokenHelper;
import com.web.student_register.entity.*;
import com.web.student_register.repository.RoleRePo;
import com.web.student_register.repository.UserRepo;
import com.web.student_register.response.LogInResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class CustomUserService implements UserDetailsService {
    private UserRepo userRepo;
    private AuthenticationManager authenticationManager;
    private JWTTokenHelper jwtTokenHelper;
    private PasswordEncoder passwordEncoder;
    private RoleRePo roleRepo;


    @Lazy
    @Autowired
    public CustomUserService(UserRepo userRepo, AuthenticationManager authenticationManager, JWTTokenHelper jwtTokenHelper, PasswordEncoder passwordEncoder, RoleRePo roleRepo) {
        this.userRepo = userRepo;
        this.authenticationManager = authenticationManager;
        this.jwtTokenHelper = jwtTokenHelper;
        this.passwordEncoder = passwordEncoder;
        this.roleRepo = roleRepo;

    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepo.getByUserName(username);

        if(user == null){
            throw new UsernameNotFoundException(username + " does not exist!");
        }
        return new UserPrincipal(user);
    }

    public User registerUser(UserDto usersDto) {
        User  user = new User();
        user.setUserName(usersDto.getUserName());
        user.setPassword(passwordEncoder.encode(usersDto.getPassword()));
        Role role = roleRepo.getByRoleName(usersDto.getRoleName());
        System.out.println("Role Name " + role.getRoleName());
        user.addRole(role);
        return userRepo.save(user);
    }

    public LogInResponse userLogIn(UserDto userDto){

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(userDto.getUserName(), userDto.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String token;
        LogInResponse response;
        try{
            response = new LogInResponse();
            token = jwtTokenHelper.generateToken(userDetails.getUsername());
            response.setToken(token);

        }catch(Exception e){
            token = null;
            response = null;

        }

        return response;
    }


}
