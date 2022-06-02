package com.invest.microservices.auth.init;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.invest.microservices.auth.model.ERole;
import com.invest.microservices.auth.model.Role;
import com.invest.microservices.auth.model.User;
import com.invest.microservices.auth.repo.RoleRepo;
import com.invest.microservices.auth.repo.UserRepo;


@Component
public class InitData implements ApplicationRunner {

	private UserRepo userRepo;

	private RoleRepo roleRepo;
	
	private PasswordEncoder encoder;
	
	@Autowired
	public InitData(UserRepo userRepo, RoleRepo roleRepo, PasswordEncoder encoder) {
		this.userRepo = userRepo;
		this.roleRepo = roleRepo;
		this.encoder = encoder;
	}

	private void initRole() {
		Role role = new Role();
		role.setName(ERole.ROLE_USER);
		this.roleRepo.save(role);
		
		role = new Role();
		role.setName(ERole.ROLE_MODERATOR);
		this.roleRepo.save(role);
		
		role = new Role();
		role.setName(ERole.ROLE_ADMIN);
		this.roleRepo.save(role);
	}
	
	private void createUser(String username, String email, String password, ERole... rolesArr) {
		
		User user = new User();
		user.setUsername(username);
		user.setEmail(email);
		user.setPassword(encoder.encode(password));
		Set<Role> roles = new HashSet<>();
		user.setRoles(roles);
		
		for(ERole role : rolesArr) {
			Role r = this.roleRepo.findByName(role).get();
			roles.add(r);
		}
		this.userRepo.save(user);
	}
	
	@Override
	public void run(ApplicationArguments args) throws Exception {
		this.initRole();
		
		this.createUser("nhutpham", "nhut.pham@ilogic.vn", "123456", ERole.ROLE_ADMIN);
		this.createUser("abc", "abc@ilogic.vn", "123456", ERole.ROLE_USER);
	}

}