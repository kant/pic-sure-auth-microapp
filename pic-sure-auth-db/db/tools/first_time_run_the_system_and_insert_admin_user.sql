#configuration for user table
#for quick usage, please use a google user
#otherwise you need to modify connection configuration as well
set @user_uuid=REPLACE(uuid(),'-','');
set @user_email="change_me_to_your_email";
set @matched=false;

#configuration for connection table
set @connection_uuid=REPLACE(uuid(),'-','');
set @label='Google';
set @id='google-oauth2';
set @subprefix='google-oauth2|';
set @requiredFields='[{\"label\":\"Email\", \"id\":\"email\"}]';

#configuration for userMetadataMapping table
set @userMetadataMapping_uuid=REPLACE(uuid(),'-','');
set @authMetadata='$.email';
set @generalMetadata='$.email';

begin;
#### insert into connection table
insert into `connection` values (unhex(@connection_uuid), @label, @id, @subprefix, @requiredFields);

#### insert into user table
create or replace view management_view as
select
role.uuid, role.name as role_name, privilege.name as privilege_name
from
role, role_privilege, privilege
where

role.uuid = role_privilege.role_id
and privilege.uuid = role_privilege.privilege_id;

insert into user (`uuid`,`general_metadata`,`connectionId`,`email`,`matched`) values (unhex(@user_uuid), CONCAT("{\"email\":\"", @user_email, "\"}"), unhex(@connection_uuid), @user_email, @matched);
insert into user_role (`user_id`,`role_id`) values (unhex(@user_uuid),
(select min(uuid) from management_view where privilege_name like 'ADMIN')) ;

#### insert into userMetadataMapping
insert into `userMetadataMapping` values (unhex(@userMetadataMapping_uuid), @authMetadata, unhex(@connection_uuid), @generalMetadata);
commit;

