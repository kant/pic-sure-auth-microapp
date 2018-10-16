require.config({
	baseUrl: "/admin/",
	paths: {
		jquery: 'webjars/jquery/3.3.1/jquery.min',
		underscore: 'webjars/underscorejs/1.8.3/underscore-min',
		handlebars: 'webjars/handlebars/4.0.5/handlebars.min',
		bootstrap: 'webjars/bootstrap/3.3.7-1/js/bootstrap.min',
		backbone: 'webjars/backbonejs/1.3.3/backbone-min',
		text: 'webjars/requirejs-text/2.0.15/text',
		'auth0-js': "webjars/auth0.js/9.2.3/build/auth0",
        Noty: 'webjars/noty/3.1.4/lib/noty'
    },
    shim: {
        "bootstrap": {
            deps: ["jquery"]
        },
        "auth0-js": {
            deps:["jquery"],
            exports: "Auth0Lock"
        }
    }
});

require(["common/startup"], function(){
});
