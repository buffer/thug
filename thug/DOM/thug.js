/*
 * Window object 
 * Javascript objects visibility
 */

//this.eval     = window.eval;
this.unescape = window.unescape;
this.decodeURIComponent = window.decodeURIComponent;
this.console = window.console;
window = this;
window.top = this;

Document.prototype = window.document;
HTMLElement.prototype = window.document.createElement("p");
HTMLIFrameElement.prototype = window.document.createElement("iframe");
HTMLImageElement.prototype = window.document.createElement("img");
HTMLScriptElement.prototype = window.document.createElement("script");
XMLHttpRequest.prototype = new XMLHttpRequest;

Object.defineProperty(window, "location", {
	set: function(value){
		window.setLocation(value);
	},
	get: function(){
		return window.getLocation();
	}
});
