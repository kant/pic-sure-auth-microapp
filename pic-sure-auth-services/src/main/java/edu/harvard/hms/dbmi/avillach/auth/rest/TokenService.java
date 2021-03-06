package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.dbmi.avillach.util.exception.ApplicationException;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.ApplicationRepository;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.UserRepository;
import edu.harvard.hms.dbmi.avillach.auth.service.auth.AuthorizationService;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Path("/token")
public class TokenService {

	private Logger logger = LoggerFactory.getLogger(TokenService.class);

	@Inject
	UserRepository userRepo;

	@Inject
	ApplicationRepository applicationRepo;

	@Inject
	AuthorizationService authorizationService;

	@Context
	SecurityContext securityContext;

	@POST
	@Path("/inspect")
	@Consumes("application/json")
	public Response inspectToken(Map<String, Object> inputMap,
			@QueryParam(value = "applicationId") String applicationId){
		logger.info("TokenInspect starting...");
		TokenInspection tokenInspection = _inspectToken(inputMap);
		if (tokenInspection.message != null)
			tokenInspection.responseMap.put("message", tokenInspection.message);

		logger.info("Finished token introspection.");
		return PICSUREResponse.success(tokenInspection.responseMap);
	}

	/**
	 * @param inputMap
	 * @return
	 */
	private TokenInspection _inspectToken(Map<String, Object> inputMap){
		logger.debug("_inspectToken, the incoming token map is: " + inputMap.entrySet()
		.stream()
		.map(entry -> entry.getKey() + " - " + entry.getValue())
		.collect(Collectors.joining(", ")));

		TokenInspection tokenInspection = new TokenInspection();

		String token = (String)inputMap.get("token");
		logger.debug("getting token: " + token);
		if (token == null || token.isEmpty()){
			logger.error("Token - "+ token + " is blank");
			tokenInspection.message = "Token not found";
			return tokenInspection;
		}

		// parse the token based on client secret
		// don't need to check if jws is null or not, since parse function has already checked
		Jws<Claims> jws;
		try {
			jws = AuthUtils.parseToken(JAXRSConfiguration.clientSecret, token);
		} catch (NotAuthorizedException ex) {
			tokenInspection.message = ex.getChallenges().toString();
			return tokenInspection;
		}

		Application application = null;

		try {
			application = (Application) securityContext.getUserPrincipal();
		} catch (ClassCastException ex){
			logger.error(securityContext.getUserPrincipal().getName()
							+ " - " + securityContext.getUserPrincipal().getClass().getSimpleName() +
					" - is trying to use token introspection endpoint" +
					", but it is not an application");
			throw new ApplicationException("The application token does not associate with an application but "
					+ securityContext.getUserPrincipal().getClass().getSimpleName());
		}

		String subject = jws.getBody().getSubject();

		// get the user based on subject field in token
		User user;

		user = userRepo.getUniqueResultByColumn("subject", subject);
		logger.info("_inspectToken() user with subject - " + subject + " - exists in database");
		if (user == null) {
			logger.error("_inspectToken() could not find user with subject " + subject);
			tokenInspection.message = "user doesn't exist";
			return tokenInspection;
		}

		//Essentially we want to return jws.getBody() with an additional active: true field
		//only under certain circumstances, the token will return active
		Set<String> privilegeNameSet = null;
		if (user != null
				&& user.getRoles() != null
				&& (application.getPrivileges().isEmpty() || ! user.getPrivilegeNameSetByApplication(application).isEmpty())
				&& authorizationService.isAuthorized(application.getName(), inputMap.get("request"), user.getUuid())) {
			tokenInspection.responseMap.put("active", true);
			ArrayList<String> roles = new ArrayList<String>();
			for(Privilege p : user.getTotalPrivilege()) {
				roles.add(p.getName());
			}
			tokenInspection.responseMap.put("roles", String.join(",",  roles));
			
		}

		tokenInspection.responseMap.putAll(jws.getBody());

		// add all privileges into response based on application
		// if no application in request, return all privileges for now
		if (application != null) {
			tokenInspection.responseMap.put("privileges", user.getPrivilegeNameSetByApplication(application));
		} else {
			if (privilegeNameSet != null && !privilegeNameSet.isEmpty())
				tokenInspection.responseMap.put("privileges", privilegeNameSet);
		}

		logger.info("_inspectToken() Successfully inspect and return response map: "
				+ tokenInspection.responseMap.entrySet()
				.stream()
				.map(entry -> entry.getKey() + " - " + entry.getValue())
				.collect(Collectors.joining(", ")));
		return tokenInspection;
	}

	/**
	 * inner used token introspection class with active:false included
	 */
	private class TokenInspection {
		Map<String, Object> responseMap = new HashMap<>();
		String message = null;

		public TokenInspection() {
			responseMap.put("active", false);
		}
	}

}
