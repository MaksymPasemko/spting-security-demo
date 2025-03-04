package com.ltp.springsecuritydemo.service;

import com.ltp.springsecuritydemo.model.User;
import com.ltp.springsecuritydemo.model.UserPrincipal;
import com.ltp.springsecuritydemo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MyUserDetailService implements UserDetailsService {
    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        final User user = userRepository.findByUsername(username);

        if(user == null){
            throw new UsernameNotFoundException("Not found");
        }

        return new UserPrincipal(user);
    }
}
