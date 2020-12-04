const request = require('request-promise');

class PeachFactory {

	constructor({
		origin,
		getAuthorisation,
		repeatedTriggerDelay = 10,
		checkedOutMax = 3,
		postAuthFetchFeeze = 2000,
		maxAttemptsPerRequest = 3,
		verifySsl = true,
		logRequests = true,
		retryAfterHeader = 'Retry-After'
	}) {

		this.queue = [];

		this.origin = origin;

		this.maxAttemptsPerRequest = maxAttemptsPerRequest;

		this.checkedOut = 0;
		this.checkedOutMax = checkedOutMax;
		this.postAuthFetchFeeze = postAuthFetchFeeze;

		this.freezeUntil = null;

		this.verifySsl = verifySsl;
		this.logRequests = logRequests;
		this.retryAfterHeader = retryAfterHeader.toLowerCase();
		this.repeatedTriggerDelay = repeatedTriggerDelay;

		this.authBeingUpdatedPromises = [];
		this.auth = null;
		this.latestRequestFactoryAuthVersion = 0;

		if (typeof getAuthorisation === 'object') {
			getAuthorisation = this.getStandardAuthorisationFunction(getAuthorisation);
		}

		this.getAuthorisation = getAuthorisation;

		this.repeatedTrigger();

	}

	getStandardAuthorisationFunction(getAuthorisation) {
		if (getAuthorisation == null) {
			return () => {
				throw new Error('Cannot fetch authorisation with no authorisation object or function passed');
			};
		}
		switch (getAuthorisation.auth_method) {
			case 'oauth2':
			return async () => {
				return await request({
					method: 'POST',
					uri: getAuthorisation.uri,
					headers: {
						Authorization: 'Basic ' + Buffer.from(getAuthorisation.client_id + ':' + getAuthorisation.client_secret).toString('base64'),
						'Content-Type': 'application/x-www-form-urlencoded'
					},
					form: {
						grant_type: 'client_credentials'
					},
					json: true
				});
			};
		}
		throw new Error(`${getAuthorisation.auth_method} is an unknown/unsupported authorisation method`);
	}

	async getNewAuthObject() {
		if (typeof this.getAuthorisation !== 'function') {
			throw new Error('Factory attempted to update authorisation but no authorisation function was provided'); 
		}
		const {token_type, access_token, expires_at, expires_in} = await this.getAuthorisation();
		if (typeof token_type !== 'string') {
			throw new Error(`Call to getAuthorisation function returned a non-string token_type: "${token_type}"`);
		}
		if (typeof access_token !== 'string') {
			throw new Error(`Call to getAuthorisation function returned a non-string access_token: "${access_token}"`);
		}
		let altered_expires_at;
		if (expires_at instanceof Date) {
			altered_expires_at = expires_at;
		} else if (Number.isInteger(expires_in)) {
			altered_expires_at = new Date(Date.now() + (expires_in * 1000))
		} else {
			throw new Error(`Call to getAuthorisation function returned a non-Date expires_at: "${expires_at}"`);
		}
		return {token_type, access_token, expires_at: altered_expires_at, version: ++this.latestRequestFactoryAuthVersion};
	}

	getAuthProperty(forceRefresh) {
		return new Promise(async (resolve, reject) => {
			if (!forceRefresh && this.auth != null && this.auth.expires_at > new Date()) {
				resolve(this.auth);
				return;
			}
			this.authBeingUpdatedPromises.push({resolve, reject});
			if (this.authBeingUpdatedPromises.length === 1) {
				let error = null;
				let authObject = null
				try {
					authObject = await this.getNewAuthObject();
					this.auth = authObject;
				} catch (err) {
					error = err;
				} finally {
					while (this.authBeingUpdatedPromises.length > 0) {
						const poppedItem = this.authBeingUpdatedPromises.pop();
						if (error) {
							poppedItem.reject(error);
						} else {
							poppedItem.resolve(authObject);
						}
					}
					this.freezeFor(this.postAuthFetchFeeze);
				}
			}
		});
	}

	async getAuth(forceRefresh) {
		const auth = await this.getAuthProperty(forceRefresh);
		switch(auth.token_type) {
			case 'Bearer':
			return {header: 'Bearer ' + auth.access_token, version: auth.version};
		}
		throw new Error(`Received an invalid token_type from getAuthorisation function "${auth.token_type}"`);
	}

	freezeFor(freezeFor) {
		if (freezeFor > 0) {
			const freezeUntil = new Date(Date.now() + freezeFor);
			if (!(this.freezeUntil instanceof Date) || this.freezeUntil < freezeUntil) {
				this.freezeUntil = freezeUntil;
			}
		}
	}

	getQueue() {
		return this.queue;
	}

	pauseIfFrozen() {
		return new Promise((resolve, reject) => {
			const freezeUntil = this.freezeUntil;
			if (!(freezeUntil instanceof Date)) {
				resolve();
				return;
			}
			const delay = freezeUntil.valueOf() - (new Date()).valueOf();
			if (delay <= 0) {
				resolve();
				return;
			}
			setTimeout(async () => {
				await this.pauseIfFrozen();
				if (freezeUntil.valueOf() === this.freezeUntil.valueOf()) {
					this.freezeUntil = null;
				}
				resolve();
			}, delay);
		});

	}

	async doQueueItem(queueItem) {

		const settings = {
			method: queueItem.options.method,
			uri: this.origin + queueItem.options.path,
			body: queueItem.options.data,
			headers: (typeof queueItem.options.headers === 'object' && queueItem.options.headers != null) ? queueItem.options.headers : {},
			json: !queueItem.options.notJson,
			resolveWithFullResponse: true,
			rejectUnauthorized: this.verifySsl
		};

		// Setup auth

		let authType;
		let requestFactoryAuthVersion;

		if (queueItem.options.auth != null) {

			if (typeof queueItem.options.auth === 'function') {
				authType = 'CustomFunction';
				settings.headers.Authorization = await queueItem.options.auth(queueItem.forceAuthRefresh);
			} else {
				authType = 'CustomStatic';
				settings.headers.Authorization = queueItem.options.auth
			}

		} else if (this.getAuthorisation) {
			authType = 'RequestFactory';
			const {version, header} = await this.getAuth(queueItem.forceAuthRefresh);
			requestFactoryAuthVersion = version;
			settings.headers.Authorization = header;
		}
		queueItem.forceAuthRefresh = false;

		// Pause if frozen
		await this.pauseIfFrozen();

		// log request
		if (this.logRequests) {
			console.log(settings);
		}

		// Do request
		let resp;
		try {
			resp = await request(settings);
		} catch (err) {

			switch(err.statusCode) {
				case 401:
					if (authType === 'RequestFactory') {
						if (this.auth != null && requestFactoryAuthVersion === this.latestRequestFactoryAuthVersion) {
							this.auth = null;
						}
					} else if (authType === 'CustomFunction') {
						queueItem.forceAuthRefresh = true;
					}
				break;
				case 429:
					const retryAfter = Number(response.response.headers['retry-after']) * 1000;
					this.freezeFor(retryAfter);
				break;
			}

			throw err;

		}

		return resp;

	}

	repeatedTrigger() {
		this.triggerNextQueueItem();
		setTimeout(() => {
			this.repeatedTrigger();
		}, this.repeatedTriggerDelay);
	}

	// This function should NEVER throw exceptions
	async triggerNextQueueItem() {

		if (this.queue.length === 0 || this.checkedOut >= this.checkedOutMax) {
			return;
		}

		const queueItem = this.queue.shift();
		if (queueItem == null) {
			return;
		}

		this.checkedOut++;

		try {
			const response = await this.doQueueItem(queueItem);
			queueItem.resolve(response);
		} catch (err) {
			queueItem.attempts++;
			if (err.statusCode == null) { // Not a failure directly from the request
				console.error(`An error occurred with the request factory (${this.origin}) and there was an error it could not handle:`, err);
				this.queue.unshift(queueItem);
				this.triggerNextQueueItem();
			} else if (queueItem.attempts >= this.maxAttemptsPerRequest) {
				console.error(`Failed RequestFactory Request (Attempt ${queueItem.attempts}/${this.maxAttemptsPerRequest}):`, queueItem, err);
				queueItem.reject(err);
			} else {
				console.warn(`Failed RequestFactory Request (Attempt ${queueItem.attempts}/${this.maxAttemptsPerRequest}):`,queueItem, err);
				this.queue.unshift(queueItem);
				this.triggerNextQueueItem();
			}
		} finally {
			this.checkedOut--;
		}

	}

	do(options) { // options should contain .method, .path and (optionally) .data and .token attributes

		return new Promise((resolve, reject) => {

			this.queue.push({
				options: options,
				attempts: 0,
				forceAuthRefresh: false,
				resolve: resolve,
				reject: reject
			});

			this.triggerNextQueueItem();

		});

	}

	doPriority(options) {

		return new Promise((resolve, reject) => {

			this.queue.unshift({
				options: options,
				attempts: 0,
				forceAuthRefresh: false,
				resolve: resolve,
				reject: reject
			});

			this.triggerNextQueueItem();

		});

	}

}

module.exports.PeachFactory = PeachFactory;
