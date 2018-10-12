define([], function(){
	// TODO : This will be integrated with a backend service when one exists.
	var connections =  [
		{
			label:"BCH", 
			id:"ldap-connector",
			subPrefix:"ldap-connector|", 
			requiredFields:[{label:"BCH Email", id:"BCHEmail"}]
		}
		,{
			label:"Google", 
			id:"google-oauth2",
			subPrefix:"google-oauth2|", 
			requiredFields:[{label:"Gmail", id:"GMail"}]
		}
	];
	return connections;
});