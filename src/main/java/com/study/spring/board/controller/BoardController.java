package com.study.spring.board.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/bbs")
@EnableMethodSecurity
public class BoardController {

	@GetMapping("/")
	@PreAuthorize("hasAnyRole('ROLE_ADMIN')")
	public String bbsList() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		return "view - User: " + auth.getName() + ", Authorities: " + auth.getAuthorities();
	}
	
	@GetMapping("/test")
	public String test() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		return "Test - User: " + auth.getName() + ", Authorities: " + auth.getAuthorities();
	}
}
