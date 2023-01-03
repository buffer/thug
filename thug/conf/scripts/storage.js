Object.defineProperty(this, 'sessionStorage', { 
	get: function() {
		return 1/0;
	}
});

Object.defineProperty(this, 'localStorage', {
        get: function() {
                return 1/0;
        }
});
