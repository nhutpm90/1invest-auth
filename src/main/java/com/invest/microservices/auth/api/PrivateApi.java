package com.invest.microservices.auth.api;

import java.util.Date;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class PrivateApi {

	@RequestMapping("/testing-01")
	public @ResponseBody String testingPrivate01() {
		return "testing-01 " + new Date();
	}
	
	@RequestMapping("/testing-02")
	public @ResponseBody String testingPrivate02() {
		return "testing-02 " + new Date();
	}
	
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	@RequestMapping("/testing-03")
	public @ResponseBody String testingPrivate03() {
		return "testing-03 " + new Date();
	}
}

