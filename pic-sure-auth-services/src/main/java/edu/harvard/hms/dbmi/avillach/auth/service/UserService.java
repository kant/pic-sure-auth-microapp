package edu.harvard.hms.dbmi.avillach.auth.service;

import edu.harvard.dbmi.avillach.util.PicsureNaming;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.User;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.transaction.Transactional;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import java.util.List;
import java.util.UUID;

/**
 * Service handling business logic for CRUD on users
 */
@Path("/user")
public class UserService extends BaseEntityService<User>{

	Logger logger = LoggerFactory.getLogger(UserService.class);

	@Inject
	UserRepository userRepo;

	public UserService() {
		super(User.class);
	}

	@GET
	@RolesAllowed(PicsureNaming.RoleNaming.ROLE_SYSTEM)
	@Path("/{userId}")
	public Response getUserById(
			@Context SecurityContext securityContext, 
			@PathParam("userId") String userId) {
		logger.info("User Management Audit Trail : " + securityContext.getUserPrincipal().getName() + " retrieved user " + userId);   
		return getEntityById(userId,userRepo);
	}

	@GET
	@RolesAllowed(PicsureNaming.RoleNaming.ROLE_SYSTEM)
	@Path("")
	public Response getUserAll(@Context SecurityContext securityContext) {
		logger.info("User Management Audit Trail : " + securityContext.getUserPrincipal().getName() + " retrieved all users");   
		return getEntityAll(userRepo);
	}

	@POST
	@RolesAllowed(PicsureNaming.RoleNaming.ROLE_SYSTEM)
	@Consumes(MediaType.APPLICATION_JSON)
	@Path("/")
	public Response addUser(@Context SecurityContext securityContext, List<User> users){
		users.stream().forEach((user)->{
			logger.info("User Management Audit Trail : " + securityContext.getUserPrincipal().getName() + " adding user entity for connectionId " + user.getConnectionId() + " with metadata " +  user.getGeneralMetadata() + " and roles " + user.getRoles());    			
		});
		return addEntity(users, userRepo);
	}

	@POST
	@RolesAllowed(PicsureNaming.RoleNaming.ROLE_SYSTEM)
	@Consumes(MediaType.APPLICATION_JSON)
	@Path("/{uuid}/role/{role}")
	public Response changeRole(
			@Context SecurityContext securityContext, 
			@PathParam("uuid") String uuid,
			@PathParam("role") String role){
		User user = userRepo.getById(UUID.fromString(uuid));
		if (user == null)
			return PICSUREResponse.protocolError("User is not found by given user ID: " + uuid);

		logger.info("User Management Audit Trail : " + securityContext.getUserPrincipal().getName() + " updating user entity " + uuid + " to have roles " + role);

		User updatedUser = userRepo.changeRole(user, role);

		return PICSUREResponse.success("User has new role: " + updatedUser.getRoles(), updatedUser);
	}

	@GET
	@RolesAllowed(PicsureNaming.RoleNaming.ROLE_SYSTEM)
	@Path("/availableRoles")
	public Response availableRoles(){
		return PICSUREResponse.success(PicsureNaming.RoleNaming.allRoles());
	}

	@PUT
	@RolesAllowed(PicsureNaming.RoleNaming.ROLE_SYSTEM)
	@Consumes(MediaType.APPLICATION_JSON)
	@Path("/")
	public Response updateUser(@Context SecurityContext securityContext, List<User> users){
		users.stream().forEach((user)->{
			logger.info("User Management Audit Trail : " + securityContext.getUserPrincipal().getName() + " updating user entity " + user.getUuid() + " to have roles " + user.getRoles());
		});
		return updateEntity(users, userRepo);
	}

	@Transactional
	@DELETE
	@RolesAllowed(PicsureNaming.RoleNaming.ROLE_SYSTEM)
	@Path("/{userId}")
	public Response removeById(@Context SecurityContext securityContext, @PathParam("userId") final String userId) {
		if(securityContext != null) {
			logger.info("User Management Audit Trail : " + securityContext.getUserPrincipal().getName() + " deleting user entity with uuid " + userId);
		}
		return removeEntityById(userId, userRepo);
	}

}
