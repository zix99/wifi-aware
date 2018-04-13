#!/usr/bin/env node
const pcap = require('pcap2');
//const wifi = require('node-wifi');
const cp = require('child_process');
const _ = require('lodash');

function setChannel(c) {
	cp.exec(`iwconfig wlp3s0 channel ${c}`);
	console.log(`Set channel to ${c}`);
}

let lastChannel = 1;
function rotateChannel() {
	lastChannel++;
	if (lastChannel > 54)
		lastChannel = 1;
	setChannel(lastChannel);
}

setInterval(rotateChannel, 1000);
setChannel(lastChannel);


sess = new pcap.Session('wlp3s0', {});

const beacons = {};
const clients = {};

sess.on('packet', raw => {
	try {
		let packet = pcap.decode.packet(raw);
		let frame = packet.payload.ieee802_11Frame;

		// Manage beacon
		if (frame.beacon) {
			console.dir(packet);
			let mac = frame.shost.toString();
			let ssid = _.find(frame.beacon.tags, tag => tag.type === 'ssid');

			if (!beacons[mac]) {
				beacons[mac] = {
					count: 0,
					name: null,
					freq: packet.payload.frequency,
					channel: (packet.payload.frequency - 2412 + 5) / 5,
				};
			}
			beacons[mac].count++;

			if (ssid) {
				beacons[mac].name = ssid.value.toString().replace('\0', '');
			}
		} else {
			// Manage any other traffic
			//console.dir(frame);
			const smac = frame.shost.toString();
			if (!clients[smac]) {
				clients[smac] = {
					data: 0,
					count: 0,
					probes: {},
					bssid: null,
				};
			}

			clients[smac].data += packet.pcap_header.len;
			clients[smac].count++;

			if (frame.probe) {
				console.log('Probe');
				//console.dir(frame.probe);
				const ssid = _.find(frame.probe.tags, x => x.type === 'ssid');
				if (ssid) {
					const ssidn = ssid.value.toString();
					if (!clients[smac].probes[ssidn])
						clients[smac].probes[ssidn] = 0;
					clients[smac].probes[ssidn]++;
				}

				_.each(frame.probe.tags, tag => {
					console.log(smac);
					console.log(`  ${tag.type}: ${tag.value.toString()}`);
				});
			} else {
				const bssid = frame.bssid.toString();
				clients[smac].bssid = bssid;
				clients[smac].bssid_name = _.get(beacons, `${bssid}.name`, 'UKN');
			}
		}

		console.log('---------------------------------------');
		console.log('Beacons:');
		_.each(beacons, (beacon, mac) => {
			console.log(`  ${mac} (Chan: ${beacon.channel}) [${beacon.count}]   ${beacon.name}`);
		});
		console.log('');
		console.log('Clients:');
		_.each(clients, (client, mac) => {
			console.log(`  ${mac} -> ${client.bssid} (${client.bssid_name})          Probes: ${_.keys(client.probes).join()}`);
		});
		//console.dir(beacons);
		//console.dir(clients);
	} catch (err) {
		console.log(err);
	}
})