package edu.harvard.hms.dbmi.avillach.auth.service;

import com.auth0.exception.Auth0Exception;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.UserMetadataMapping;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;

public class Auth0UserMatchingService {

	@Autowired
	UserRepository userRepo;

	@Autowired
	UserMetadataMappingService mappingService;

	private Logger logger = LoggerFactory.getLogger(Auth0UserMatchingService.class);

	private ObjectMapper mapper = new ObjectMapper();

	public String mockAuthAPIUserInfo(String accessToken) {
		Map<String, String> map = Map.of("ldap-connector-access-token",
				"{    \"name\": \"Guy,Some\",    \"family_name\": \"Guy\",    \"given_name\": \"Some\",    \"nickname\": \"CH000000000\",    \"groups\": [],    \"emails\": [        \"foo@childrens.harvard.edu\"    ],    \"dn\": \"CN=CH0000000,OU=users,DC=chbdir,DC=org\",    \"distinguishedName\": \"CN=CH0000000,OU=users,DC=chbdir,DC=org\",    \"organizationUnits\": \"CN=CH0000000,OU=users,DC=chbdir,DC=org\",    \"email\": \"foo@childrens.harvard.edu\",    \"updated_at\": \"2018-10-04T18:28:23.371Z\",    \"picture\": \"https://s.gravatar.com/avatar/blablablablablablablablablablablabla?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fsp.png\",    \"user_id\": \"ad|ldap-connector|blablablablablablablablablablablabla\",    \"identities\": [        {            \"user_id\": \"ldap-connector|blablablablablablablablablablablabla\",            \"provider\": \"ad\",            \"connection\": \"ldap-connector\",            \"isSocial\": false        }    ],    \"created_at\": \"2018-01-26T14:06:50.413Z\",    \"username\": \"CH0000000\",    \"app_metadata\": {        \"roles\": [            \"ROLE_CITI_USER\"        ]    },    \"last_ip\": \"134.174.140.32\",    \"last_login\": \"2018-10-04T18:28:23.091Z\",    \"logins_count\": 399,    \"blocked_for\": [],    \"guardian_authenticators\": []}",
				"github-access-token", "  {    \"email\": \"blablabla@gmail.com\",    \"name\": \"Some Girl\",    \"picture\": \"https://avatars3.githubusercontent.com/u/0000000000?v=4\",    \"nickname\": \"blablabla\",    \"gravatar_id\": \"\",    \"url\": \"https://api.github.com/users/blablabla\",    \"html_url\": \"https://github.com/blablabla\",    \"followers_url\": \"https://api.github.com/users/blablabla/followers\",    \"following_url\": \"https://api.github.com/users/blablabla/following{/other_user}\",    \"gists_url\": \"https://api.github.com/users/blablabla/gists{/gist_id}\",    \"starred_url\": \"https://api.github.com/users/blablabla/starred{/owner}{/repo}\",    \"subscriptions_url\": \"https://api.github.com/users/blablabla/subscriptions\",    \"organizations_url\": \"https://api.github.com/users/blablabla/orgs\",    \"repos_url\": \"https://api.github.com/users/blablabla/repos\",    \"events_url\": \"https://api.github.com/users/blablabla/events{/privacy}\",    \"received_events_url\": \"https://api.github.com/users/blablabla/received_events\",    \"type\": \"User\",    \"site_admin\": false,    \"location\": \"Nowhere, USA\",    \"hireable\": true,    \"public_repos\": 8,    \"public_gists\": 0,    \"followers\": 3,    \"following\": 1,    \"updated_at\": \"2018-09-20T18:47:43.703Z\",    \"emails\": [        {            \"email\": \"blablabla@gmail.com\",            \"primary\": true,            \"verified\": true,            \"visibility\": \"public\"        },        {            \"email\": \"blablabla@users.noreply.github.com\",            \"primary\": false,            \"verified\": true,            \"visibility\": null        }    ],    \"email_verified\": true,    \"user_id\": \"github|0000000\",    \"identities\": [        {            \"provider\": \"github\",            \"user_id\": 000000000,            \"connection\": \"github\",            \"isSocial\": true        }    ],    \"created_at\": \"2016-10-22T22:38:20.437Z\",    \"blog\": \"\",    \"node_id\": \"blablabla=\",    \"app_metadata\": {        \"roles\": [            \"ROLE_CITI_USER\"        ]    },    \"last_ip\": \"134.174.140.198\",    \"last_login\": \"2018-09-20T18:47:43.491Z\",    \"logins_count\": 71,    \"blocked_for\": [],    \"guardian_authenticators\": []}",
				"nih-gov-prod-access-token","  {    \"email\": \"NOBODY\",    \"sessionIndex\": \"blablablabla\",    \"UserPrincipalName\": \"\",    \"Mail\": \"\",    \"FirstName\": \"\",    \"LastName\": \"\",    \"MiddleName\": \"\",    \"NEDID\": \"\",    \"nameIdAttributes\": {        \"value\": \"NOBODY\",        \"Format\": \"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\"    },    \"authenticationmethod\": \"urn:oasis:names:tc:SAML:2.0:ac:classes:Password\",    \"issuer\": \"https://auth.nih.gov/IDP\",    \"updated_at\": \"2018-07-23T19:32:51.505Z\",    \"name\": \"\",    \"picture\": \"https://cdn.auth0.com/avatars/default.png\",    \"user_id\": \"samlp|NOBODY\",    \"nickname\": \"\",    \"identities\": [        {            \"user_id\": \"NOBODY\",            \"provider\": \"samlp\",            \"connection\": \"nih-gov-prod\",            \"isSocial\": false        }    ],    \"created_at\": \"2018-04-02T13:10:25.654Z\",    \"app_metadata\": {        \"roles\": [            \"ROLE_CITI_USER\"        ]    },    \"last_ip\": \"134.174.140.195\",    \"last_login\": \"2018-07-23T19:32:51.254Z\",    \"logins_count\": 12,    \"blocked_for\": [],    \"guardian_authenticators\": []}",
				"no-mapping-connection-token","  {    \"email\": \"foo@bar.com\",     \"UserName\": \"foooo\",     \"FirstName\": \"foo\",    \"LastName\": \"oooo\",\"user_id\": \"samlp|fooBar\",    \"identities\": [        {            \"user_id\": \"fooBar\",            \"provider\": \"samlp\",            \"connection\": \"no-mapping-connection\",            \"isSocial\": false        }    ]}",
				"invalid-path-token","  {    \"email\": \"bar@foo.com\",     \"UserName\": \"bahh\",     \"user_id\": \"samlp|barFoo\",    \"identities\": [        {            \"user_id\": \"barFoo\",            \"provider\": \"samlp\",            \"connection\": \"invalid-path\",            \"isSocial\": true        }    ]}",
				"no-user-token","  {    \"email\": \"no@user.com\",     \"UserName\": \"nooooooo\",     \"user_id\": \"samlp|noUser\",    \"identities\": [        {            \"user_id\": \"noUser\",            \"provider\": \"samlp\",            \"connection\": \"no-user-connection\",            \"isSocial\": false        }    ]}"
		);
		return map.get(accessToken);
	}


	/**
	 * Retrieve a user profile by access_token and match it to a pre-created user in the database using
	 * pre-configured matching rules. 
	 * 
	 * @param access_token An auth0 access_token acquired through the login flow.
	 * @return The user that was matched or null if no match was possible.
	 * @throws Auth0Exception
	 */
	public User matchTokenToUser(String access_token) throws Auth0Exception, JsonProcessingException {
		// This retrieves a map of UserInfo as JSON.
/*
		USE THIS FOR REAL TIMES

		UserInfo info = new AuthAPI("avillachlab.auth0.com", "", "").userInfo(access_token).execute();

		// Available as a map, but can always be ObjectMapper'd back to JSON for matching using libraries that do such things
		Map<String, Object> infoValues = info.getValues();
		String userInfo = mapper.writeValueAsString(infoValues);
*/
		/* Replace this with the above*/
		String userInfo = mockAuthAPIUserInfo(access_token);
		/**/

		//Parse this once so it doesn't get re-parsed every time we read from it
		Configuration conf = Configuration.defaultConfiguration().addOptions(Option.DEFAULT_PATH_LEAF_TO_NULL).addOptions(Option.ALWAYS_RETURN_LIST);
		Object parsedInfo = conf.jsonProvider().parse(userInfo);
		//Return lists or null so that we don't have to worry about whether it's a single object or an array, or catch errors
		conf = conf.addOptions(Option.DEFAULT_PATH_LEAF_TO_NULL).addOptions(Option.ALWAYS_RETURN_LIST);
			List<String> connections = JsonPath.using(conf).parse(parsedInfo).read("$.identities[0].connection");
			String connection = connections.get(0);
			List<UserMetadataMapping> mappings = mappingService.getAllMappingsForConnection(connection);

			if (mappings == null || mappings.isEmpty()){
				logger.info("Unable to find mappings for connectionId " + connection);
				//We don't have any mappings for this connection yet
				addNewUser(userInfo);
				return null;
			}
			//We only care about unmatched users
			List<User> users = userRepo.listUnmatchedByConnectionId(connection);
			if (users == null || users.isEmpty()){
				logger.info("No unmatched users exist with connectionId " + connection);
				addNewUser(userInfo);
				return null;
			}
			for (UserMetadataMapping umm : mappings){
				List<String> auth0values = JsonPath.using(conf).parse(parsedInfo).read(umm.getAuth0MetadataJsonPath());
				if (auth0values == null || auth0values.isEmpty()){
					//Well, nothing found, let's move on.
					logger.info("Fetched data has no value at " + umm.getAuth0MetadataJsonPath());
					break;
				}
				String auth0value = auth0values.get(0);
				for (User u : users) {
					List<String> values = JsonPath.using(conf).parse(u.getGeneralMetadata()).read(umm.getGeneralMetadataJsonPath());
					if (values == null || values.isEmpty()){
						logger.info("User " + u.getUuid() + " has no value at " + umm.getGeneralMetadataJsonPath());
						break;
					}
					String generalValue = values.get(0);
					if (auth0value.equalsIgnoreCase(generalValue)) {
						//Match found!!
						String userId = JsonPath.read(parsedInfo, "$.user_id");
						logger.info("Matching user with user_id " + userId);
						u.setAuth0metadata(userInfo);
						u.setMatched(true);
						u.setSubject(userId);
						userRepo.persist(u);
						return u;
					}
				}
			}
			//No user found; create a new one
			addNewUser(userInfo);

		return null;
	}

	private void addNewUser(String userInfo){
		String userId = JsonPath.read(userInfo, "$.user_id");
		logger.info("Adding new user with id " + userId);
		User newUser = new User();
		newUser.setAuth0metadata(userInfo);
		newUser.setSubject(userId);
		userRepo.persist(newUser);
	}
	
}
