var saved_eval = eval;

this.eval = function() {
	window.%s = arguments[0];
	saved_eval(arguments[0]);
}
