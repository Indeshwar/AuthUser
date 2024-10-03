package com.web.student_register.Dto;


import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class UserDto {
    private String name;
    private String userName;
    private String password;
    private String roleName;

}
