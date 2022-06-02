package com.invest.microservices.auth.repo;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.invest.microservices.auth.model.ERole;
import com.invest.microservices.auth.model.Role;

@Repository
public interface RoleRepo extends JpaRepository<Role, Long> {

	Optional<Role> findByName(ERole name);
}