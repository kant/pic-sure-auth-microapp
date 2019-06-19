define(["backbone","handlebars", "text!header/header.hbs", "common/session", "picSure/userFunctions","picSure/applicationFunctions", "text!options/modal.hbs","text!header/userProfile.hbs", "picSure/tokenFunctions"],
		function(BB, HBS, template, session, userFunctions, applicationFunctions,modalTemplate, userProfileTemplate, tokenFunctions){
	var headerView = BB.View.extend({
        initialize: function () {
            HBS.registerHelper('not_contains', function (array, object, opts) {
                var found = _.find(array, function (element) {
                    return (element === object);
                });
                if (found)
                    return opts.inverse(this);
                else
                    return opts.fn(this);
            });
            this.template = HBS.compile(template);
            this.applications = [];
            this.modalTemplate = HBS.compile(modalTemplate);
            this.userProfileTemplate = HBS.compile(userProfileTemplate);
        },
        events: {
            "click #logout-btn": "gotoLogin",
            "click #user-profile-btn": "userProfile"
        },
        gotoLogin: function (event) {
            this.logout();
            window.location = "/psamaui/login" + window.location.search;
        },
        userProfile: function (event) {
            userFunctions.me(this, function(user){
                $("#modal-window").html(this.modalTemplate({title: "User Profile"}));
                $("#modalDialog").show();
                $(".modal-body").html(this.userProfileTemplate({user:user, token: session.token()}));
                $("#user-token-copy-button").click(this.copyToken);
                $("#user-token-refresh-button").click(this.refreshToken);
            }.bind(this));
        },
        copyToken: function(){
            var sel = getSelection();
            var range = document.createRange();

            // this if for supporting chrome, since chrome will look for value instead of textContent
            document.getElementById("user_token_textarea").value = document.getElementById("user_token_textarea").textContent;

            range.selectNode(document.getElementById("user_token_textarea"));
            sel.removeAllRanges();
            sel.addRange(range);
            document.execCommand("copy");

            $("#user-token-copy-button").html("COPIED");
        },
        refreshToken: function(){
            var currentToken = session.token();
            tokenFunctions.refreshToken(currentToken,function(response){
                var token = response.token;
                $("#user_token_textarea").html(token);
                $("#user-token-copy-button").html("COPY");
                session.setToken(token);
            }.bind(this));
        },
        logout: function (event) {
            sessionStorage.clear();
            localStorage.clear();
        },
        render: function () {
            if (window.location.pathname !== "/psamaui/tos") {
                userFunctions.me(this, function (user) {
                    applicationFunctions.fetchApplications(this, function(applications){
                        this.applications = applications;
                        this.$el.html(this.template({
                            privileges: user.privileges,
                            applications: this.applications
                                .filter(function (app) {
                                    return app.url;
                                })
                                .sort(function(a, b){
                                    if(a.name < b.name) { return -1; }
                                    if(a.name > b.name) { return 1; }
                                    return 0;
                                })
                        }));
                    }.bind(this))

                }.bind(this));
            }
        }
    });

	return {
		View : new headerView({})
	};
});
