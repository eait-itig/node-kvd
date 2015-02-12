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

var crypto = require('crypto');

var int_to_op = {
	0: "create",
	1: "created",
	2: "request",
	3: "value",
	4: "novalue",
	5: "delete",
	6: "deleted",
	7: "sync",
	10: "update",
	11: "updated",
	12: "checksig"
};

var op_to_int = {
	"create": 0,
	"created": 1,
	"request": 2,
	"value": 3,
	"novalue": 4,
	"delete": 5,
	"deleted": 6,
	"sync": 7,
	"update": 10,
	"updated": 11,
	"checksig": 12
};

var int_to_sigtype = {
	1: "hmac-sha1",
	2: "hmac-sha256",
	3: "rsa-sha1",
	4: "rsa-sha256"
};

var sigtype_to_int = {
	"hmac-sha1": 1,
	"hmac-sha256": 2,
	"rsa-sha1": 3,
	"rsa-sha256": 4
};

function decodeCheckSig(rem) {
	var uidLen = rem.readUInt8(0);
	var uid = rem.slice(1, uidLen + 1);
	rem = rem.slice(uidLen + 1);
	var sigType = rem.readUInt8(0);
	rem = rem.slice(1);
	var sigLen = rem.readUInt8(0);
	var sig = rem.slice(1, sigLen + 1);
	var data = rem.slice(sigLen + 1);
	return {
		uid: uid.toString('utf8'),
		type: int_to_sigtype[sigType],
		signature: sig,
		data: data
	};
}

function encodeCheckSig(obj) {
	var uidBuf = new Buffer(obj.uid.length + 1);
	uidBuf.writeUInt8(obj.uid.length, 0);
	uidBuf.write(obj.uid, 1, obj.uid.length, 'utf8');
	var sigBuf = new Buffer(2);
	sigBuf.writeUInt8(sigtype_to_int[obj.type], 0);
	sigBuf.writeUInt8(obj.signature.length, 1);
	return Buffer.concat([uidBuf, sigBuf, obj.signature, obj.data]);
}

function decode(msg) {
	/* the second byte must always be null */
	if (msg.readUInt8(1) !== 0)
		return false;

	var size = msg.readUInt16BE(2);
	var op = msg.readUInt8(0);

	/* check the length of the payload. for historical reasons, we ignore the length bytes
	   if it's a CREATED packet, and just check we got 32 bytes back.  */
	if (op !== op_to_int['created'] && size !== (msg.length - 4 - 32))
		return false;
	if (op === op_to_int['created'] && msg.length !== 4 + 32 + 32)
		return false;

	var key = msg.slice(4, 36);
	for (var i = 0; i < 32; ++i) {
		if (key[i] === 0) {
			key = key.slice(0,i);
			break;
		}
	}
	key = key.toString('ascii');

	var payload = msg.slice(36);
	if (payload.length > 0) {
		/* parse a checksig payload */
		if (op === op_to_int['checksig']) {
			payload = decodeCheckSig(payload);
		/* 123 == '{', all JSON objects have to start with it */
		} else if (payload[0] === 123) {
			payload = JSON.parse(payload.toString('utf8'));

		} else {
			payload = payload.toString('utf8');
		}
	} else {
		payload = undefined;
	}

	return {
		op: int_to_op[op],
		key: key,
		payload: payload
	};
}

function encode(obj) {
	var payload = new Buffer(0);
	if (obj.op === 'checksig')
		payload = encodeCheckSig(obj.payload);
	else if (obj.payload && typeof obj.payload === 'string')
		payload = new Buffer(obj.payload, 'utf8');
	else if (obj.payload && obj.payload instanceof Buffer)
		payload = obj.payload;
	else if (obj.payload)
		payload = new Buffer(JSON.stringify(obj.payload), 'utf8');

	var key = new Buffer(32);
	key.fill(0);
	key.write(obj.key, 0, 32, 'ascii');

	var hdr = new Buffer(4);
	hdr.writeUInt8(op_to_int[obj.op], 0);
	hdr.writeUInt8(0, 1);
	hdr.writeUInt16BE(payload.length, 2);

	return Buffer.concat([hdr, key, payload]);
}

var cookieChars = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
function genCookie() {
	var randbuf = crypto.randomBytes(64);
	var cookie = "";
	for (var i = 0; i < 64; i += 2) {
		var idx = randbuf.readUInt16LE(i) % cookieChars.length;
		cookie += cookieChars.slice(idx, idx+1);
	}
	return cookie;
}

module.exports = {
	op_to_int: op_to_int,
	int_to_op: int_to_op,
	encode: encode,
	decode: decode,
	generateCookie: genCookie
}
