define(["auth/login", "common/layout"],
		function(login, layout){
	console.log("in startup");
	if( (! localStorage.id_token) || (new Date().getTime() - localStorage.expires_at > 0)){
		login.showLoginPage();
	}else{
		layout();
	}
});