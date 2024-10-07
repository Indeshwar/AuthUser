package com.web.student_register;

import com.web.student_register.Service.CustomUserService;
import com.web.student_register.Service.EmailService;
import com.web.student_register.config.JWTTokenHelper;
import com.web.student_register.entity.User;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

@SpringBootTest
public class ServiceTest {
    @Autowired
    private EmailService emailService;
    @Autowired
    private CustomUserService userService;

    @Autowired
    private JWTTokenHelper jwtTokenHelper;

    @Test
    public void sendEmaiTest(){
        String email = "indeshc@gmail.com";
        String subject = "Email Test";
        String text = "Demo Email Testing";
        emailService.sendEmail(email, subject, text);
//        Mockito.verify(emailService).sendEmail(email, subject, test);
    }

    @Test
    public void forgetPassword(){
        String token = userService.forgetPassword("shekhar", null);
        int requestCount = jwtTokenHelper.getRequestCount(token);
        long timeStamp = jwtTokenHelper.getTimeStamp(token);
        System.out.println("token: " + token);
        System.out.println("request count : " + requestCount);
        System.out.println("time stamp : " + timeStamp);
    }

    @Test
    public void resetPasswordTest(){
        userService.resetPassword("eyJhbGciOiJSUzI1NiJ9.eyJ0aW1lU3RhbXAiOjE3MjgzMzY3NTA4NDMsInJlcXVlc3RDb3VudCI6MSwic3ViIjoic2hla2hhciIsImV4cCI6MTcyODM0MDM1MCwiaWF0IjoxNzI4MzM2NzUwfQ.XinUjHaRtdb_K1VujxDUByX29XiocQgmcJHzGbeedxhYpZPFud-mz3SBpKU62DtMZqIkKZdpTXV5g_HMTojGOnGZ2DhDz4B9I390wiU6O041vO3O3UicZAY61ndBbUp8NU8K6yLNU56HcDxo-OiueWxaIBpm3HhAKqVByme6exGEQj5jByfg0pan2H3CFoApMR7W6SyY26PhJetrpQoB3kOkXZ0QUKZyR-r19Q8-nSn2FqW8UYYZEmsoTRDuVrW6NqVpM69Mde3aV2v0vzSl3wbQSn8PGLCMO6Znzd-qpCBchIIHriqiaAOz-R-Tjtrzdq5OK6zH2SVlJh_AkkT_N1YdteXRMYu52bZoMbLdldtqdc9pNAXFXDbHpD1x_V5dunhkbtZVyvJBF5EHCbgW32dupSqO32Los8Qywcct_otl0RIDt9M0WA9Ew2NZfdxGXdLYf1qXjCvsNq4Ght8GN8OnfIlhKeb87NyswnHRAFYVcv1kWqUPpv6DUBOUsjXPBHkDcoqaZCIVk-41sR22BIKMDXSkLwgzIFWh6CLHTiY7fdXNNz6dHBkBvMoAIKN4fFDN0elEL6-U5sFOhWxlJwqNAZwZyg0zXU38um5bA-sXvFKtnnnSCgSCmh0M3oHjkQDgk6mDAaEu6RTkoYnvKHPFWjMJ3FpG8VRpG3Hmflo", "shekhar123");
        System.out.println("Password is updated");
    }


}
