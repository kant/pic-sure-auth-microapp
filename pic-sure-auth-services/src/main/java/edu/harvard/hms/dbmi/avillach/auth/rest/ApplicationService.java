package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.dbmi.avillach.util.exception.ApplicationException;
import edu.harvard.dbmi.avillach.util.exception.ProtocolException;
import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.Application;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.ApplicationRepository;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.PrivilegeRepository;
import edu.harvard.hms.dbmi.avillach.auth.service.BaseEntityService;
import edu.harvard.hms.dbmi.avillach.auth.utils.JWTUtil;
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
import java.util.*;

import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.ADMIN;
import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.SUPER_ADMIN;

@Path("/application")
public class ApplicationService extends BaseEntityService<Application> {

	private static final long ONE_YEAR = 1000L * 60 * 60 * 24 * 365;

	Logger logger = LoggerFactory.getLogger(ApplicationService.class);

	@Inject
	ApplicationRepository applicationRepo;

	@Inject
	PrivilegeRepository privilegeRepo;

	@Context
	SecurityContext securityContext;

	public ApplicationService() {
		super(Application.class);
	}

	@GET
	@Path("/{applicationId}")
	@RolesAllowed({ADMIN, SUPER_ADMIN})
	public Response getApplicationById(
			@PathParam("applicationId") String applicationId) {
		return getEntityById(applicationId,applicationRepo);
	}

	@GET
	@Path("")
	@RolesAllowed({ADMIN, SUPER_ADMIN})
	public Response getApplicationAll() {
		return getEntityAll(applicationRepo);
	}

	@Transactional
	@POST
	@RolesAllowed({SUPER_ADMIN})
	@Consumes(MediaType.APPLICATION_JSON)
	@Path("/")
	public Response addApplication(List<Application> applications){
		checkAssociation(applications);
		List<Application> appEntities = addOrUpdate(applications, true, applicationRepo);
		for(Application application : appEntities) {
			try{
				application.setToken(
						generateApplicationToken(application)
				);
			} catch(Exception e) {
				logger.error("", e);
			}
		}

		return updateEntity(appEntities, applicationRepo);
	}

	@PUT
	@RolesAllowed({SUPER_ADMIN})
	@Consumes(MediaType.APPLICATION_JSON)
	@Path("/")
	public Response updateApplication(List<Application> applications){
		checkAssociation(applications);
		return updateEntity(applications, applicationRepo);
	}

	@GET
	@RolesAllowed({SUPER_ADMIN})
	@Path("/refreshToken/{applicationId}")
	public Response refreshApplicationToken(@PathParam("applicationId") String applicationId){
		Application application = applicationRepo.getById(UUID.fromString(applicationId));

		if (application == null){
			logger.error("refreshApplicationToken() cannot find the application by applicationId: " + applicationId);
			throw new ProtocolException("Cannot find application by the given applicationId: " + applicationId);
		}

		String newToken = generateApplicationToken(application);
		if (newToken != null){
			application.setToken(
				newToken
			);

			applicationRepo.merge(application);
		} else {
			logger.error("refreshApplicationToken() token is null for application: " + applicationId);
			throw new ApplicationException("Inner problem, please contact admin");
		}

		return PICSUREResponse.success(Map.of("token", newToken));

	}

	@Transactional
	@DELETE
	@RolesAllowed({SUPER_ADMIN})
	@Path("/{applicationId}")
	public Response removeById(@PathParam("applicationId") final String applicationId) {
		Application application = applicationRepo.getById(UUID.fromString(applicationId));
		return removeEntityById(applicationId, applicationRepo);
	}

	private void checkAssociation(List<Application> applications){
		for (Application application: applications){
			if (application.getPrivileges() != null) {
				Set<Privilege> privileges = new HashSet<>();
				application.getPrivileges().stream().forEach(p -> {
					Privilege privilege = privilegeRepo.getById(p.getUuid());
					if (privilege != null){
						privilege.setApplication(application);
						privileges.add(privilege);
					} else {
						logger.error("Didn't find privilege by uuid: " + p.getUuid());
					}
				});
				application.setPrivileges(privileges);

			}
		}

	}

	public String generateApplicationToken(Application application){
		if (application == null || application.getUuid() == null) {
			logger.error("generateApplicationToken() application is null or uuid is missing to generate the application token");
			throw new ApplicationException("Cannot generate application token, please contact admin");
		}

		return JWTUtil.createJwtToken(
				JAXRSConfiguration.clientSecret, null, null,
				new HashMap<>(
						Map.of(
								"user_id","PSAMA_APPLICATION|" + application.getName()
						)
				),
				"PSAMA_APPLICATION|" + application.getUuid().toString(), 365L * 1000 * 60 * 60 * 24);
	}
}
