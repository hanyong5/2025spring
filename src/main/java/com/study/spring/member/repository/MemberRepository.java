package com.study.spring.member.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.study.spring.member.entity.Member;

public interface MemberRepository extends JpaRepository<Member, Long> {

	//방법1 
//	@Query("select m from Member m left join fetch m.memberRoleList where m.email = :email")
//	Optional<Member> findByEmail(@Param("email") String email);

	//방법2
//	@EntityGraph(attributePaths = "memberRoleList")
//	@Query("select m from Member m where m.email = :email")
//	Optional<Member> findByEmail(@Param("email") String email);
	
	//방법3
	@EntityGraph(attributePaths = "memberRoleList")
	Optional<Member> findByEmail(String email);

	

	
	
	
}
