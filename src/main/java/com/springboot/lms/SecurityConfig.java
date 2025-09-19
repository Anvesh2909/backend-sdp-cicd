package com.springboot.lms;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // IMPORTANT: Use setAllowedOriginPatterns instead of setAllowedOrigins for better compatibility
        configuration.setAllowedOriginPatterns(Arrays.asList(
                "http://localhost:5173",
                "http://184.72.170.131:5173"
        ));

        // Explicitly allow all necessary methods
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"));

        // Allow all headers
        configuration.setAllowedHeaders(Arrays.asList("*"));

        // Allow credentials
        configuration.setAllowCredentials(true);

        // Set max age for preflight cache
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, JwtFilter jwtFilter) throws Exception {
        http
                // Configure CORS FIRST
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // Disable CSRF
                .csrf(csrf -> csrf.disable())

                // Configure authorization
                .authorizeHttpRequests(authorize -> authorize
                        // Allow ALL OPTIONS requests
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // Public endpoints
                        .requestMatchers("/api/user/signup").permitAll()
                        .requestMatchers("/api/author/register").permitAll()
                        .requestMatchers("/api/learner/add").permitAll()
                        .requestMatchers("/api/author/add").permitAll()
                        .requestMatchers("/api/course/getAll").permitAll()

                        // Authenticated endpoints
                        .requestMatchers("/api/user/token").authenticated()
                        .requestMatchers("/api/user/details").authenticated()
                        .requestMatchers("/api/course/getCoursesByAuthor").hasAuthority("AUTHOR")
                        .requestMatchers("/api/module/add").hasAuthority("AUTHOR")
                        .requestMatchers("/api/learner/getLearner").hasAuthority("LEARNER")
                        .requestMatchers("/api/video/add/{moduleId}").hasAuthority("AUTHOR")
                        .requestMatchers("/api/course/add").hasAnyAuthority("AUTHOR", "EXECUTIVE")

                        .anyRequest().authenticated()
                )

                // Add JWT filter AFTER CORS is configured
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationManager getAuthManager(AuthenticationConfiguration auth) throws Exception {
        return auth.getAuthenticationManager();
    }
}