package com.web.student_register.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
@Slf4j
@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JWTTokenHelper jwtTokenHelper;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = jwtTokenHelper.getToken(request);
        if(token != null){
            System.out.println("token -------> " + token);
            String userName = jwtTokenHelper.getUserNameFromToken(token);
            System.out.println("name -------> " + userName);
            if(userName != null){
                UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
                if(jwtTokenHelper.validateToken(token, userDetails)){
                    System.out.println("token -------> validated");
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails.getUsername(),
                            null, userDetails.getAuthorities());
                    authentication.setDetails( new WebAuthenticationDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }

            }
        }

        filterChain.doFilter(request, response);
    }

}
