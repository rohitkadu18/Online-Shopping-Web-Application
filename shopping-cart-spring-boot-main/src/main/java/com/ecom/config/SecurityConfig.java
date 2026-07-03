package com.ecom.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    // FIX 1: Inject by concrete class, not the interface.
    // Autowiring AuthenticationSuccessHandler (interface) failed because
    // AuthSucessHandlerImpl was registered by class name, not interface type.
    @Autowired
    private AuthSucessHandlerImpl authenticationSuccessHandler;

    @Autowired
    @Lazy
    private AuthFailureHandlerImpl authenticationFailureHandler;

    // FIX 2: Inject the existing @Service bean instead of creating "new UserDetailsServiceImpl()".
    // The old code created a raw instance bypassing Spring DI — the @Autowired
    // UserRepository inside it was null, so no users could ever be loaded.
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider auth = new DaoAuthenticationProvider();
        auth.setUserDetailsService(userDetailsService);
        auth.setPasswordEncoder(passwordEncoder());
        return auth;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
            .csrf(csrf -> csrf.disable())

            // FIX 3: Register the provider on the http chain.
            // Without this line, Spring Security uses its own default provider
            // which ignores your users — authentication "works" but roles are
            // empty, so hasRole("ADMIN") always returns 403.
            .authenticationProvider(authenticationProvider())

            .authorizeHttpRequests(req -> req
                .requestMatchers(
                    "/",
                    "/register",
                    "/saveUser",
                    "/signin",
                    "/login",
                    "/forgot-password",
                    "/reset-password",
                    "/products/**",
                    "/product/**",
                    "/search",
                    "/css/**",
                    "/js/**",
                    "/img/**"
                ).permitAll()
                .requestMatchers("/user/**").hasRole("USER")
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )

            .formLogin(form -> form
                .loginPage("/signin")
                .loginProcessingUrl("/login")
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler)
            )

            .logout(logout -> logout.permitAll());

        return http.build();
    }
}
