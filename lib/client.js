/*
node-kvd
KVD client for node.js

Copyright (c) 2015, Alex Wilson and the University of Queensland
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation and/or
   other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

var proto = require('./protocol');
var dgram = require('dgram');

function KVDClient(remote, port) {
	if (!port)
		port = 1080;
	this.socket = dgram.createSocket('udp4');
	this.socket.on('message', handleMessage.bind(this));
	this.socket.bind();

	this.remote = remote;
	this.port = port;

	this.reqs = {};
	Object.keys(proto.op_to_int).forEach(function(k) { this.reqs[k] = {}; }.bind(this));

	this.timeout = 200;
	this.getTimeout = 50;
	this.retries = 10;
}

function handleMessage(msg, rinfo) {
	msg = proto.decode(msg);
	switch (msg.op) {
		case 'value':
		case 'novalue':
		case 'created':
		case 'deleted':
		case 'updated':
			if (this.reqs[msg.op][msg.key])
				this.reqs[msg.op][msg.key].message(msg);
			else
				console.log("unsolicited kvd '"+msg.op+"' for key '" + msg.key + "'");
			break;

		default:
			console.log("unknown kvd op received", msg);
	}
}

KVDClient.prototype.get = function(key, bucket, cb) {
	if (!cb && typeof bucket !== 'string') {
		cb = bucket;
		bucket = undefined;
	}
	if (this.reqs['value'][key]) {
		this.reqs['value'][key].on("finish", cb);
	} else {
		var op = {op: 'request', key: key, payload: bucket};
		var req = new Request(this, key, op);
		req.timeout = this.getTimeout;
		req.on("finish", cb);
		req.send();
	}
}

KVDClient.prototype.create = function(payload, cb) {
	var cookie = proto.generateCookie();
	var op = {op: 'create', key: cookie, payload: payload};
	var req = new Request(this, cookie, op);
	req.on("finish", cb);
	req.send();
}

KVDClient.prototype.update = function(key, payload, cb) {
	var op = {op: 'update', key: key, payload: payload};
	var req = new Request(this, key, op);
	req.on("finish", cb);
	req.send();
}

KVDClient.prototype.delete = function(key, cb) {
	var op = {op: 'delete', key: key};
	var req = new Request(this, key, op);
	req.on("finish", cb);
	req.send();
}

KVDClient.prototype.checkSignature = function(type, uid, signature, data, cb) {
	var cookie = proto.generateCookie();
	var op = {op: 'checksig', key: cookie, payload: {
		type: type, uid: uid, signature: signature, data: data
	}};
	var req = new Request(this, cookie, op);
	req.on("finish", cb);
	req.send();
}

module.exports = KVDClient;

function Request(client, key, op) {
	this.client = client;
	this.op = op;
	this.cbs = [];
	this.key = key;
	this.retries = client.retries;
	this.timeout = client.timeout;
}

Request.prototype.on = function(evt, cb) {
	if (evt === "finish")
		this.cbs.push(cb);
}

function handleTimeout() {
	if (!this.timer)
		return;
	delete this.timer;
	if (this.retries > 0) {
		this.send();
	} else {
		this.finish("KVD request timed out");
	}
}

Request.prototype.send = function() {
	var msg = proto.encode(this.op);
	switch (this.op.op) {
		case 'request':
		case 'checksig':
			this.client.reqs.value[this.key] = this;
			this.client.reqs.novalue[this.key] = this;
			break;
		case 'create':
			this.client.reqs.created[this.key] = this;
			break;
		case 'delete':
			this.client.reqs.deleted[this.key] = this;
			break;
		case 'update':
			this.client.reqs.updated[this.key] = this;
			break;
	}
	this.client.socket.send(msg, 0, msg.length, this.client.port, this.client.remote);
	this.timer = setTimeout(handleTimeout.bind(this), this.timeout);
	this.retries -= 1;
	this.timeout *= 2;
	if (this.timeout > 2000)
		this.timeout = 2000;
}

Request.prototype.message = function(msg) {
	if (this.timer)
		clearTimeout(this.timer);
	delete this.timer;

	switch (msg.op) {
		case 'value':
		case 'created':
			return this.finish(null, msg.payload);
		case 'novalue':
		case 'deleted':
		case 'updated':
			return this.finish(null);
	}
}

Request.prototype.finish = function(err, val) {
	Object.keys(proto.op_to_int).forEach(function(k) {
		delete this.client.reqs[k][this.key];
	}.bind(this));
	this.cbs.forEach(function(cb) {
		cb(err, val);
	});
}
