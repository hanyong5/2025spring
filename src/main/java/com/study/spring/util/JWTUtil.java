package com.study.spring.util;

import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Map;

import javax.crypto.SecretKey;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.InvalidClaimException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;

public class JWTUtil {
	
	private static String key = "123456789123456789123456789123456789";

	public static String generateToken(Map<String, Object> claims, int i) {
		
		SecretKey key = null;
		
		try {
			key = Keys.hmacShaKeyFor(JWTUtil.key.getBytes("UTF-8"));
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage());
		}
		
		String jwtStr = Jwts.builder()
				.setHeader(Map.of("typ","JWT"))
				.setClaims(claims)
				.setIssuedAt(Date.from(ZonedDateTime.now().toInstant()))
				.setExpiration(Date.from(ZonedDateTime.now().plusMinutes(i).toInstant()))
				.signWith(key)
				.compact();
		
		return jwtStr;
	}
	
	public static Map<String, Object> validateToken(String token) {

	    Map<String, Object> claim = null;
	    
	    try{
	      System.out.println("Validating token: " + token);

	      SecretKey key = Keys.hmacShaKeyFor(JWTUtil.key.getBytes("UTF-8"));

	      claim = Jwts.parserBuilder()
	              .setSigningKey(key)
	              .build()
	              .parseClaimsJws(token) // 파싱 및 검증, 실패 시 에러
	              .getBody();
	              
	      System.out.println("Token validation successful, claims: " + claim);
	    }catch(MalformedJwtException malformedJwtException){
            throw new CustomJWTException("MalFormed"); 
            // 잘못된 형식의 JWT가 전달된 경우
        }catch(ExpiredJwtException expiredJwtException){
            throw new CustomJWTException("Expired"); 
            // 만료된 JWT가 전달된 경우
        }catch(InvalidClaimException invalidClaimException){
            throw new CustomJWTException("Invalid"); 
            // JWT의 클레임이 유효하지 않은 경우
        }catch(JwtException jwtException){
            throw new CustomJWTException("JWTError"); 
            // 기타 JWT 관련 오류 발생 시
        }catch(Exception e){
            throw new CustomJWTException("Error");
            // 그 외의 예외 발생 시
        }
	    return claim;
	  }

}
