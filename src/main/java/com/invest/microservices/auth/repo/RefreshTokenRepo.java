package com.invest.microservices.auth.repo;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.invest.microservices.auth.model.RefreshToken;

public interface RefreshTokenRepo extends JpaRepository<RefreshToken, Long> {
	
	Optional<RefreshToken> findById(Long id);

	Optional<RefreshToken> findByToken(String token);
}
