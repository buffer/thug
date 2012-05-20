"use strict";

/*
 * Window object 
 * Javascript objects visibility
 */

window.Array    = Array;
window.Boolean  = Boolean;
window.Date     = Date;
window.Math     = Math;
window.Number   = Number;
window.RegExp   = RegExp;
window.String   = String;
window.unescape = unescape;

window._Function = Function;
Function = function(code) {
	if (code.indexOf("@cc_on!@") >= 0) {
		code = code.replace("@cc_on!@", "*/!/*");
	}
	return window._Function(code);
}
