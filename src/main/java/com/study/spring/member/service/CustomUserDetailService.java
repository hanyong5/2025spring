package com.study.spring.member.service;

import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.study.spring.member.dto.MemberDto;
import com.study.spring.member.entity.Member;
import com.study.spring.member.repository.MemberRepository;

import lombok.extern.log4j.Log4j2;

@Service
@Log4j2
public class CustomUserDetailService implements UserDetailsService{
	
	@Autowired
	private MemberRepository memberRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		log.info("**************load user by username *********************"+ username);
		
		Optional<Member> member = memberRepository.findByEmail(username);
		
		if(!member.isPresent()) {
			throw new UsernameNotFoundException("사용자를 찾을수 없습니다. **" + username);
		}
		
		
		log.info("----> "+member+" <----");
		
		MemberDto memberDto = new MemberDto(
				member.get().getEmail(),
				member.get().getPassword(),
				member.get().getNickname(),
				member.get().isSocial(),
				member.get().getMemberRoleList().stream()
					.map(memberRole -> memberRole.name())
					.collect(Collectors.toList())
				
				);
		log.info("### member ### ///// "+memberDto);
		
		return memberDto;
	}

}
