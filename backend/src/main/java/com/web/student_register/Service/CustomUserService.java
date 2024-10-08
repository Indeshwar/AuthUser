package com.web.student_register.Service;

import com.web.student_register.Dto.UserDto;
import com.web.student_register.config.JWTTokenHelper;
import com.web.student_register.entity.*;
import com.web.student_register.exception.InvalidTokenException;
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
    private static final int MAX_REQUEST = 3;
    // TIME_FRAME is 1 hour
    private static final long TIME_FRAME = 60 * 60 * 1000;

    @Autowired
    private EmailService emailService;





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
            throw new UsernameNotFoundException("userName is " + username + " does not exist!");
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
            token = jwtTokenHelper.generateToken(userDetails.getUsername(), 0);
            response.setToken(token);

        }catch(Exception e){
            token = null;
            response = null;

        }

        return response;
    }

    public String forgetPassword(String email, String token){
        String newToken = null;
        try {

            if(token != null){
                String userName = jwtTokenHelper.getUserNameFromToken(token);
                UserDetails userDetails = loadUserByUsername(userName);

                //Validate the token
                if(!jwtTokenHelper.validateToken(token, userDetails)){
                    return "Token expired. Try again";
                }

                int requestCount = jwtTokenHelper.getRequestCount(token);
                long timeStamp = jwtTokenHelper.getTimeStamp(token);

                //Check if user exceed the limit
                if(requestCount > MAX_REQUEST &&  System.currentTimeMillis() - timeStamp < TIME_FRAME){
                    return "To many password reset Request. Try again Later";
                }


                //increment the request count and create new Token
                newToken = jwtTokenHelper.generateToken(userName, requestCount + 1);

            }else{
                //create new token if a user first time request for password reset
                UserDetails user = loadUserByUsername(email);
                newToken = jwtTokenHelper.generateToken(user.getUsername(), 1);
            }

            //Create Url
            String url = createURL(newToken);
            //send reset link to the user
            emailService.sendEmail("indeshc@gmail.com", "Demo URL", "Click the reset password Link " + url);
        }catch(Exception e){
            throw new InvalidTokenException("Token is invalid", e);
        }
        return newToken;
    }

    public String createURL(String token){
        return "https://www.chicagolandtharusociety.org/" + token;
    }

    public void resetPassword(String token, String newPassword){
        String userName = jwtTokenHelper.getUserNameFromToken(token);
        if(userName != null){
            UserDetails userDetails = loadUserByUsername(userName);
            if(jwtTokenHelper.validateToken(token, userDetails)){
                User user = userRepo.getByUserName(userName);
                user.setPassword(passwordEncoder.encode(newPassword));
                userRepo.save(user);
            }
        }

    }


}
