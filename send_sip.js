'use strict';

const dgram = require('dgram');
const client = dgram.createSocket('udp4');

var makePayload = (forceConnectIP) => {return `INVITE sip:root@${forceConnectIP} SIP/2.0\n\rVia: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKkjshdyff\n\rTo: Bob <sip:root@192.168.1.205>\n\rFrom: Alice <sip:root@192.168.1.205>;tag=88sja8x\n\rMax-Forwards: 70\n\rCall-ID: 987asjd97y7atg\n\rCSeq: 986759 INVITE`};


for (let i = 0; i < 255; i++) {
	let sipip = `10.4.0.${i}`;
	let ip = '10.1.236.140';
	//let sipip = '10.4.0.65';
	let payload = makePayload(ip);
	payload = Buffer.from(payload);
	client.send(payload, 5060, sipip, (err) => {
	});

	client.on('close', function() {
	    console.log('Client UDP socket closed : BYE!');
	});
	
}
