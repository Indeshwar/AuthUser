package com.web.student_register.controller;

import com.web.student_register.Dto.UserDto;
import com.web.student_register.Service.CustomUserService;
import com.web.student_register.entity.User;
import com.web.student_register.response.LogInResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("api/v1")
public class UserController {

    @Autowired
    private CustomUserService userService;

    @GetMapping("/hello")
    public String hello(){
        return "Hello World";
    }

    @GetMapping("/student/hi")
    public String sayHi(){
        return "Hello I am authenticated user";
    }
    
    @PostMapping("/saveUser")
    public ResponseEntity<User> registerUser(@RequestBody UserDto userDto){
        User user = userService.registerUser(userDto);
        return new ResponseEntity<>(user, HttpStatus.ACCEPTED);
    }

    @PostMapping("/user/logIn")
    public ResponseEntity<LogInResponse> userLogIn(@RequestBody UserDto user){
        System.out.print("User Name " + user.getUserName());
        LogInResponse response = userService.userLogIn(user);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }


}
