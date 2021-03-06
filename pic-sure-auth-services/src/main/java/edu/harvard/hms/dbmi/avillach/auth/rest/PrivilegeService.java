package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.dbmi.avillach.util.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.Privilege;
import edu.harvard.hms.dbmi.avillach.auth.data.repository.PrivilegeRepository;
import edu.harvard.hms.dbmi.avillach.auth.service.BaseEntityService;
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

import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.ADMIN;
import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.SUPER_ADMIN;

@Path("/privilege")
public class PrivilegeService extends BaseEntityService<Privilege> {

    Logger logger = LoggerFactory.getLogger(PrivilegeService.class);

    @Inject
    PrivilegeRepository privilegeRepo;

    @Context
    SecurityContext securityContext;

    public PrivilegeService() {
        super(Privilege.class);
    }

    @GET
    @RolesAllowed({ADMIN, SUPER_ADMIN})
    @Path("/{privilegeId}")
    public Response getPrivilegeById(
            @PathParam("privilegeId") String privilegeId) {
        return getEntityById(privilegeId,privilegeRepo);
    }

    @GET
    @RolesAllowed({ADMIN, SUPER_ADMIN})
    @Path("")
    public Response getPrivilegeAll() {
        return getEntityAll(privilegeRepo);
    }

    @POST
    @RolesAllowed({SUPER_ADMIN})
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/")
    public Response addPrivilege(List<Privilege> privileges){
        return addEntity(privileges, privilegeRepo);
    }

    @PUT
    @RolesAllowed({SUPER_ADMIN})
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/")
    public Response updatePrivilege(List<Privilege> privileges){
        return updateEntity(privileges, privilegeRepo);
    }

    @Transactional
    @DELETE
    @RolesAllowed({SUPER_ADMIN})
    @Path("/{privilegeId}")
    public Response removeById(@PathParam("privilegeId") final String privilegeId) {
        Privilege privilege = privilegeRepo.getById(UUID.fromString(privilegeId));
        if (ADMIN.equals(privilege.getName())){
            logger.info("User: " + JAXRSConfiguration.getPrincipalName(securityContext)
                    + ", is trying to remove the system admin privilege: " + ADMIN);
            return PICSUREResponse.protocolError("System Admin privilege cannot be removed - uuid: " + privilege.getUuid().toString()
                    + ", name: " + privilege.getName());
        }

        return removeEntityById(privilegeId, privilegeRepo);
    }

}
