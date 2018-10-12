define(["header/header", "jquery", "user/userManagement"], 
		function(header, $, userManagement){
	var header = header;
	return function(){
		var header = this.header.View;
		header.render();
		$('#header-content').append(header.$el);

		var userMngmt = new userManagement.View({model: new userManagement.Model()});
		userMngmt.render();
		$('#user-div').append(userMngmt.$el);
	}.bind({header:header});
});