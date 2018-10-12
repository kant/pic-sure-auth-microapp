define(["backbone", "handlebars", "user/connections", "picSure/userFunctions", "text!user/addUser.hbs", "text!user/addUserConnectionForm.hbs"], 
		function(BB, HBS, connections, userFunctions, template, connectionTemplate){
	var view = BB.View.extend({
		initialize: function(){
			this.connectionTemplate = HBS.compile(connectionTemplate);
			this.template = HBS.compile(template);
			this.connections = connections;
			this.connection = this.connections[0];
		},
		events: {
			"change #new-user-connection-dropdown":"renderConnectionForm",
			"click #save-user-button": "createUser"
		},
		createUser: function(event){
			var metadata = {};
			_.each($('#current-connection-form input[type=text]'), function(entry){
				metadata[entry.name] = entry.value});
			var user = {
					connectionId: $('#new-user-connection-dropdown').val(),
					generalMetadata:JSON.stringify(metadata),
					roles: _.pluck(this.$('input:checked'),'value').join(',')
			};
			userFunctions.createOrUpdateUser(
					[user],
					"POST",
					function(result){
						console.log(result);
						this.render();
					}.bind(this)
			);
		},
		renderConnectionForm: function(event){
			this.connection = _.find(this.connections, {id:event.target.value});
			$('#current-connection-form', this.$el).html(
					this.connectionTemplate({
						connection: this.connection,
						createOrUpdateUser: true, 
						availableRoles: []
					}));
			userFunctions.getAvailableRoles(function (roles) {
				$('#current-connection-form', this.$el).html(
						this.connectionTemplate({
							connection: this.connection,
							createOrUpdateUser: true, 
							availableRoles: roles
						}));
			}.bind(this));
		},
		render: function(){
			this.$el.html(this.template({connections: this.connections}));
			this.renderConnectionForm({target:{value:this.connections[0].id}})
		}
	});
	return view;
});