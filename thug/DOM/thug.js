/*
 * Window object 
 * Javascript objects visibility
 */

//this.eval     = window.eval;
this.unescape = window.unescape;
//window = this;

Object.defineProperty(window, "location", {
	set: function(value){
		window.setLocation(value);
	},
	get: function(){
		return window.getLocation();
	}
});
