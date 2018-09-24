var %(saved)s = document.write;

document.write = function() {
	if (typeof %(name)s === "undefined") {
		window.%(name)s = new Array();
	}

	window.%(name)s.push(arguments[0]);
	%(saved)s(arguments[0]);
}
