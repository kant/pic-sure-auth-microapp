define(['common/layout', 'header/header', 'picSure/userFunctions', 'text!auth/not_authorized.hbs', 'text!settings/settings.json', 'common/searchParser', 'auth0-js', 'jquery', 'handlebars', 'text!auth/login.hbs'], 
		function(layout, header, userFunctions, notAuthorizedTemplate, settings, parseQueryString, Auth0Lock, $, HBS, loginTemplate){

	var loginTemplate = HBS.compile(loginTemplate);

	var loginCss = null
	$.get("https://avillachlab.us.webtask.io/connection_details_base64?webtask_no_cache=1&css=true", function(css){
		loginCss = "<style>" + css + "</style";
	});

	var defaultAuthorizationCheck = function(id_token, callback){
		userFunctions.fetchUsers(undefined, function(roles){
			callback([roles!==undefined])
		});
	};

	var handleAuthorizationResult = function(userIsAuthorized){
		var queryObject = parseQueryString();
		if(userIsAuthorized && typeof queryObject.access_token === "string" && typeof queryObject.id_token === "string"){
			var expiresAt = JSON.stringify(
					queryObject.expires_in * 1000 + new Date().getTime()
			);
			localStorage.setItem('access_token', queryObject.access_token);
			localStorage.setItem('id_token', queryObject.id_token);
			localStorage.setItem('expires_at', expiresAt);
			setTimeout(defaultAuthorizationCheck(queryObject.id_token, handleAuthorizationResult), queryObject.expires_in + 5000);
			window.location = '/';
		}else{
			if(typeof queryObject.access_token === "string"){
				$('#main-content').html(HBS.compile(notAuthorizedTemplate)({}));
			}else{
				var clientId = "MUPJoktRm8irc1yOqCfbP5IvAONQtK4W";
				$.ajax("https://avillachlab.us.webtask.io/connection_details_base64/?webtask_no_cache=1&client_id=" + clientId, 
						{
					dataType: "text",
					success : function(scriptResponse){
						var script = scriptResponse.replace('responseType : "code"', 'responseType : "token"');

						layout();
						
						$('#main-content').html(loginTemplate({
							buttonScript : script,
							clientId : clientId,
							auth0Subdomain : "avillachlab",
							callbackURL : window.location.protocol + "//"+ window.location.hostname + (window.location.port ? ":"+window.location.port : "") +"/login"
						}));
						$('#main-content').append(loginCss);
					}
						});
			}
		}
	}

	var login = {
			showLoginPage : function(){			
				$(document).ajaxError(function (e, xhr, options) {
					if (xhr.status == 401){
						console.log("NOT LOGGED IN");
						header.View.logout();
						handleAuthorizationResult(false);
					}
				});
				var queryObject = parseQueryString();
				if(queryObject.id_token){
					var expiresAt = JSON.stringify(
							queryObject.expires_in * 1000 + new Date().getTime()
					);
					localStorage.setItem('access_token', queryObject.access_token);
					localStorage.setItem('id_token', queryObject.id_token);
					localStorage.setItem('expires_at', expiresAt);
					setTimeout(defaultAuthorizationCheck(queryObject.id_token, handleAuthorizationResult), queryObject.expires_in + 5000);
				}


				if(localStorage.id_token){
					defaultAuthorizationCheck(localStorage.id_token, handleAuthorizationResult);
				}else{
					handleAuthorizationResult(false);
				}
			}
	};
	return login;
});

