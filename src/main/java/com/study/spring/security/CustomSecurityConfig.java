package com.study.spring.security;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.study.spring.security.handler.APILoginFailHandler;
import com.study.spring.security.handler.APILoginSuccessHandler;
import com.study.spring.security.handler.CustomAccessDeniedHandler;
import com.study.spring.util.JWTCheckFilter;

import lombok.extern.log4j.Log4j2;

@Configuration
@EnableMethodSecurity
@Log4j2
public class CustomSecurityConfig {
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		log.info("--------------------- security config ---------------------");

		http.csrf(config -> config.disable());
		http.cors(httpSecurityCorsConfigurer -> {
		      httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource());
		    });
//		http.cors(config -> config.disable());

		http.sessionManagement(config -> 
			config.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		);
		
		http.formLogin(config -> {
			config.loginPage("/api/member/login");
			config.successHandler(new APILoginSuccessHandler());
			config.failureHandler(new APILoginFailHandler());
			
		});
		
		http.addFilterBefore(new JWTCheckFilter(), UsernamePasswordAuthenticationFilter.class);
		 http.exceptionHandling(config -> {
		      config.accessDeniedHandler(new CustomAccessDeniedHandler());
		    });

		return http.build();
	}
	
	@Bean
	  public CorsConfigurationSource corsConfigurationSource() {

	    CorsConfiguration configuration = new CorsConfiguration();

	    configuration.setAllowedOriginPatterns(Arrays.asList("*"));
	    configuration.setAllowedMethods(Arrays.asList("HEAD", "GET", "POST", "PUT", "DELETE"));
	    configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
	    configuration.setAllowCredentials(true);

	    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	    source.registerCorsConfiguration("/**", configuration);

	    return source;
	  }

}
