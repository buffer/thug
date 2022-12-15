var %(saved)s = eval;

this.eval = function() {
	if (typeof %(name)s === "undefined") {
		window.%(name)s = new Array();
	}

	window.%(name)s.push(arguments[0]);
	return %(saved)s(arguments[0]);
}
