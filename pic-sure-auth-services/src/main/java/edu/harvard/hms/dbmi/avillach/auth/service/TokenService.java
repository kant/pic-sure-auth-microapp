package edu.harvard.hms.dbmi.avillach.auth.service;

import com.fasterxml.jackson.databind.JsonNode;
import edu.harvard.dbmi.avillach.util.exception.ApplicationException;
import edu.harvard.dbmi.avillach.util.exception.ResourceInterfaceException;
import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.UserRepository;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.dbmi.avillach.util.PicsureNaming;
import edu.harvard.hms.dbmi.avillach.auth.utils.HttpClientUtil;
import io.jsonwebtoken.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.utils.URLEncodedUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestParam;

import javax.annotation.Resource;
import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.persistence.NoResultException;
import javax.persistence.NonUniqueResultException;
import javax.ws.rs.*;
import javax.ws.rs.core.Response;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@Path("/token")
public class TokenService {

	private Logger logger = LoggerFactory.getLogger(TokenService.class);

	@Resource(mappedName = "java:global/client_secret")
	private String clientSecret;

	@Resource(mappedName = "java:global/auth0token")
	private String auth0token;

	@Resource(mappedName = "java:global/auth0host")
	private String auth0host;

	@Inject
	UserRepository userRepo;

	@POST
	@RolesAllowed(PicsureNaming.RoleNaming.ROLE_TOKEN_INTROSPECTION)
	@Path("/inspect")
	@Consumes("application/json")
	public Response inspectToken(Map<String, String> tokenMap,
			@QueryParam(value = "email") String email){
		logger.info("TokenInspect starting...");
		TokenInspection tokenInspection = _inspectToken(tokenMap);
		if (tokenInspection.message != null)
			tokenInspection.responseMap.put("message", tokenInspection.message);

		logger.info("Finished token introspection.");
		return PICSUREResponse.success(tokenInspection.responseMap);
	}

	private TokenInspection _inspectToken(Map<String, String> tokenMap){
		logger.debug("_inspectToken, the incoming token map is: " + tokenMap.entrySet()
		.stream()
		.map(entry -> entry.getKey() + " - " + entry.getValue())
		.collect(Collectors.joining(", ")));

		TokenInspection tokenInspection = new TokenInspection();
		tokenInspection.responseMap.put("active", false);
		String token = tokenMap.get("token");
		logger.debug("getting token: " + token);
		if (token == null || token.isEmpty()){
			logger.error("Token - "+ token + " is blank");
			tokenInspection.message = "Token not found";
			return tokenInspection;
		}

		Jws<Claims> jws = null;

		/**
		 * This parser is taking care of both clientSecret Base64 encryption and non-encryption
		 */
		try {
			jws = Jwts.parser().setSigningKey(clientSecret.getBytes()).parseClaimsJws(token);
		} catch (SignatureException e) {
			try {
				jws = Jwts.parser().setSigningKey(Base64.decodeBase64(clientSecret
						.getBytes("UTF-8")))
						.parseClaimsJws(token);
			} catch (UnsupportedEncodingException ex){
				logger.error("_inspectToken() clientSecret encoding UTF-8 is not supported. "
						+ ex.getClass().getSimpleName() + ": " + ex.getMessage());
				throw new ApplicationException("Inner problem: encoding is not supported.");
			} catch (JwtException | IllegalArgumentException ex) {
				logger.error("_inspectToken() throws: " + e.getClass().getSimpleName() + ", " + e.getMessage());
				tokenInspection.message = "error: " + e.getMessage();
				return tokenInspection;
			}
		} catch (JwtException | IllegalArgumentException e) {
			logger.error("_inspectToken() throws: " + e.getClass().getSimpleName() + ", " + e.getMessage());
			tokenInspection.message = "error: " + e.getMessage();
			return tokenInspection;
		}

		if (jws == null) {
			logger.error("_inspectToken() get null for claims by parsing Token - " + token );
			tokenInspection.message = "error: cannot get user info from the token given";
			return tokenInspection;
		}

		String subject = jws.getBody().getSubject();
		
		User user = findUserForSubject(subject);

		if(user==null) {
			logger.error("_inspectToken() unable to find user for subject" + subject);
			tokenInspection.message = "error: user not authorized";
			return tokenInspection;		
		}
		
		//Essentially we want to return jws.getBody() with an additional active: true field
		if (user.getRoles() != null
				&& user.getRoles().contains(PicsureNaming.RoleNaming.ROLE_INTROSPECTION_USER))
			tokenInspection.responseMap.put("active", true);

		
		tokenInspection.responseMap.putAll(jws.getBody());

		logger.info("_inspectToken() Successfully inspect and return response map: "
				+ tokenInspection.responseMap.entrySet()
				.stream()
				.map(entry -> entry.getKey() + " - " + entry.getValue())
				.collect(Collectors.joining(", ")));
		return tokenInspection;
	}

	public User findUserForSubject(String subject) {
		User user;
		
		try {
			user = userRepo.findBySubject(subject);
		} catch (NoResultException e) {
			user = new User().setSubject(subject).setUserId(subject);
			final String email = (getEmailForSubject(user, subject));
			List<User> unmatchedUsersForConnection = 
					userRepo.findUnmatchedForConnectionId(user.getConnectionId());
			
			Map<String, String> connectionEmailFields = 
					Map.of("google-oauth2", "GMail", "ldap-connector", "BCHEmail");
			
			List<User> usersForEmail = unmatchedUsersForConnection.stream().filter((User aUser)->{
				Map<String, String> genMeta;
				try {
					genMeta = JAXRSConfiguration.objectMapper.readValue(aUser.getGeneralMetadata(), Map.class);
					return genMeta.get(connectionEmailFields.get(aUser.getConnectionId())).equalsIgnoreCase(email);
				} catch (IOException e1) {
					logger.error("findUserForSubject() invalid JSON in general metadata for " + email);
					return false;
				}
			}).collect(Collectors.toList());
			
			if(usersForEmail.size() == 0) {
				logger.error("findUserForSubject() could not find user with email " + email);
				return null;	
			}
			
			if(usersForEmail.size() > 1) {
				logger.error("findUserForSubject() found multiple users with email " + email + " for connection " + user.getConnectionId());
				return null;	
			}
			
			user = usersForEmail.get(0)
					.setSubject(subject)
					.setEmail(email)
					.setUserId(email)
					.setMatched(true);
			
		} catch (NonUniqueResultException e) {
			logger.error("findUserForSubject() found multiple users with subject " + subject);
			return null;	

		}

		user = userRepo.merge(user);
		return user;
	}

	private String getEmailForSubject(User user, String subject) {
		Map<String, String> researchMap = new HashMap<>();
		researchMap.put("user_id", subject);
		/**
		 * now with a user, we can retrieve email info by subject from Auth0 and set to the user
		 */
		try {
			setEmailAndConnection(user, researchMap,
					auth0host);
		} catch (IOException ex){
			logger.error("IOException thrown when retrieving email from Auth0 server");
		}

		if (user.getEmail()==null || user.getEmail().isEmpty()){
			logger.error("Cannot retrieve email from auth0.");
			return null;
		} else {
			return user.getEmail();
		}
	}

	private class TokenInspection {
		Map<String, Object> responseMap = new HashMap<>();
		String message = null;
	}

	/**
	 * This method is retrieving email from Auth0 by any specific fields.
	 * Now we only support Auth0 search. If in the future, we want to support
	 * other search methods, it is better to create an interface.
	 *
	 * @return
	 */
	public void setEmailAndConnection(User user, Map<String, String> searchMap, String auth0host)
			throws IOException {

		String searchString = "";
		for (Map.Entry<String, String> entry : searchMap.entrySet()){
			searchString += URLEncoder.encode(entry.getKey() +":" + entry.getValue(), "utf-8") + "%20or%20";
		}

		if (searchString.isEmpty()) {
			logger.error("getEmail() no searchString generated." );
			return;
		}

		searchString = searchString.substring(0, searchString.length()-8);

		String requestPath = "?fields=email,identities&include_fields=true&q=" + searchString;

		String uri = auth0host + requestPath;
		HttpResponse response = HttpClientUtil.retrieveGetResponse(uri, auth0token);


		if (response.getStatusLine().getStatusCode() != 200) {
			logger.error(uri + " did not return a 200: {} {}",response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase());
			//If the result is empty, a 500 is thrown for some reason
			JsonNode responseObject = JAXRSConfiguration.objectMapper.readTree(response.getEntity().getContent());

			if (response.getStatusLine().getStatusCode() == 401) {
				logger.error("Communicating with Auth0 get a 401: " + responseObject + " with URI: " + uri);
			}
			logger.error("Error when communicating with Auth0 server" + responseObject + " with URI: " + uri);
			throw new ApplicationException("Inner application error, please contact admin.");
		}
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		response.getEntity().writeTo(out);
		byte[] content = out.toByteArray();
		System.out.println(new String(content));
		
		
		JsonNode responseJson = JAXRSConfiguration.objectMapper.readTree(new ByteArrayInputStream(content));

		logger.debug("getEmail() response from Auth0 " + JAXRSConfiguration.objectMapper.writeValueAsString(responseJson));

		if (responseJson.isArray() && responseJson.get(0) != null){
			user.setEmail(responseJson.get(0).get("email").textValue());
			user.setUserId(user.getEmail());
			user.setConnectionId(responseJson.get(0).get("identities").get(0).get("connection").textValue());
		} else {
			logger.error("getEmail() response from Auth0 is not returning an json array");
		}
	}

}
