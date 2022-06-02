package com.invest.microservices.auth.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.invest.microservices.auth.model.User;
import com.invest.microservices.auth.repo.UserRepo;
import com.invest.microservices.auth.utils.JwtUtils;

@RestController
@RequestMapping("/api/public")
public class PublicApi {

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserRepo userRepo;
	
	@Autowired
	private PasswordEncoder encoder;
	
	@Autowired
	private JwtUtils jwtUtils;

	@RequestMapping("/users")
	public String users() {
		Iterable<User> all = userRepo.findAll();

		StringBuilder sb = new StringBuilder();

		all.forEach(p -> sb.append(p.getUsername() + p.getPassword() + "<br>"));

		return sb.toString();
	}
}
