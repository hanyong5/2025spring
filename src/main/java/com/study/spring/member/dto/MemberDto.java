package com.study.spring.member.dto;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class MemberDto extends User {
	
	
	private String email;
	private String password;
	private String nickname;
	private boolean social;
	private List<String> roleNames = new ArrayList<>();

	public MemberDto(String email, String password,String nickname, boolean social, List<String> roleNames) {
		super(email,password,roleNames.stream()
				.map(str-> new SimpleGrantedAuthority("ROLE_"+str))
				.collect(Collectors.toList()));
		
		this.email = email;
		this.password = password;
		this.nickname = nickname;
		this.social = social;
		this.roleNames = roleNames;
	}
	
	
	public Map<String, Object> getClaims(){
		
		Map<String,Object> dataMap = new HashMap<>();
		dataMap.put("email", email);
		dataMap.put("password", password);
		dataMap.put("nickname", nickname);
		dataMap.put("social", social);
		dataMap.put("roleNames", roleNames);

		return dataMap;
	}
	

	

}
