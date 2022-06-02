package com.invest.microservices.auth.api;

import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
public class MainController {

	private static final Logger logger = LoggerFactory.getLogger(MainController.class);
	
	@Autowired
	private Environment environment;
	
	@Value("${app.env}")
    private String env;
	
	@GetMapping("/api/public/live-check")
	public String liveCheck() throws Exception {
		Integer port = Integer.parseInt(environment.getProperty("local.server.port"));
		String ret = "1Invest Auth Server:: port:: " + port + " - " + new Date() + " - env:: " + env;
		logger.info(ret);
		return ret; 
	}
}
