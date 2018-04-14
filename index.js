#!/usr/bin/env node
const pcap = require('pcap2');
const cp = require('child_process');
const blessed = require('blessed');
const _ = require('lodash');
const chalk = require('chalk');
const moment = require('moment');

const args = require('yargs')
	.usage('Usage: $0 [options]')
	.describe('interface', 'Interface to listen on')
	.string('interface')
	.alias('i', 'interface')
	.default('interface', 'wlan0')
	.describe('channel', 'Channel to listen on (if unspecified, rotate)')
	.number('channel')
	.help()
	.alias('h', 'help')
	.argv;

const screen = blessed.screen({
	smartCSR: true,
});

const uiHeader = blessed.Text({
	top: 0,
	left: 0,
	width: '100%',
	height: 1,
});
screen.append(uiHeader);

const uiBeacons = blessed.ListTable({
	top: 1,
	left: 0,
	width: '50%',
	height: '75%-1',
	border: { type: 'line' },
	style: {
		header: {
			bold: true,
			bg: 'green',
		},
	},
	noCellBorders: true,
	//label: 'Beacons',
});
screen.append(uiBeacons);

const uiClients = blessed.ListTable({
	top: 1,
	left: '50%',
	width: '50%',
	height: '100%-1',
	border: { type: 'line' },
	style: {
		header: {
			bold: true,
			bg: 'blue',
		},
	},
	noCellBorders: true,
	//label: 'Clients',
});
screen.append(uiClients);

const uiLog = blessed.Log({
	top: '75%',
	left: 0,
	height: '25%',
	width: '50%',
	border: { type: 'line' },
	tags: true,
	scrollback: 1000,
	label: 'Logs',
})
screen.append(uiLog);

screen.render();

function log(msg, level = 'INFO') {
	uiLog.log(`${chalk.gray(moment().format('LTS'))} [${chalk.blue(level)}] ${msg}`);
	screen.render();
}

let lastChannel = args.channel || 1;

function renderHeader() {
	uiHeader.content = `WifiAware | Intf: ${args.interface} | Chan: ${lastChannel}`;
	screen.render();
}

function setChannel(c) {
	cp.exec(`iwconfig ${args.interface} channel ${c}`);
}

function rotateChannel() {
	lastChannel++;
	if (lastChannel > 54)
		lastChannel = 1;
	setChannel(lastChannel);

	renderHeader();
}
if (!args.channel)
	setInterval(rotateChannel, 1000);
setChannel(lastChannel);
renderHeader();

sess = new pcap.Session(args.interface, {});

const beacons = {};
const clients = {};

sess.on('packet', raw => {
	try {
		let packet = pcap.decode.packet(raw);
		let frame = packet.payload.ieee802_11Frame;

		// Manage beacon
		if (frame.beacon) {
			let mac = frame.shost.toString();
			let ssid = _.find(frame.beacon.tags, tag => tag.type === 'ssid');

			if (!beacons[mac]) {
				beacons[mac] = {
					count: 0,
					name: null,
					freq: packet.payload.frequency,
					channel: (packet.payload.frequency - 2412 + 5) / 5,
					strength: packet.payload.signalStrength,
				};
			}
			beacons[mac].count++;
			beacons[mac].strength = (beacons[mac].strength + packet.payload.signalStrength) / 2;
			beacons[mac].last = moment();

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
					dmac: frame.dhost.toString(),
					strength: packet.payload.signalStrength,
				};
			}

			clients[smac].data += packet.pcap_header.len;
			clients[smac].count++;
			clients[smac].strength = (clients[smac].strength + packet.payload.signalStrength) / 2;
			clients[smac].last = moment();

			if (frame.probe) {
				//console.dir(frame.probe);
				const ssid = _.find(frame.probe.tags, x => x.type === 'ssid');
				if (ssid) {
					const ssidn = ssid.value.toString();
					if (!clients[smac].probes[ssidn])
						clients[smac].probes[ssidn] = 0;
					clients[smac].probes[ssidn]++;
				}
			} else {
				const bssid = frame.bssid.toString();
				clients[smac].bssid = bssid;
				clients[smac].bssid_name = _.get(beacons, `${bssid}.name`, 'UKN');
			}
		}
	} catch (err) {
		log(err, 'ERROR');
	}
});

function updateTables() {
	uiBeacons.setData(_.concat(
		[['BSSID', 'Chan', 'Count', 'Strength', 'Age', 'Name']],
		_.map(beacons, (beacon, mac) => [mac, `${beacon.channel}`, `${beacon.count}`, `${~~beacon.strength} dB`, `${moment().diff(beacon.last, 'seconds')}s`, beacon.name || '??'])
	));

	uiClients.setData(_.concat(
		[['MAC', 'BSSID', 'BSSID Name', 'Strength', 'Data', 'Age', 'Probes']],
		_.map(clients, (client, mac) => [mac, client.bssid || 'None', client.bssid_name || '??', `${~~client.strength} dB`, `${client.data}B`, `${moment().diff(client.last, 'seconds')}s`, _.keys(client.probes).join()])
	));

	screen.render();
}
setInterval(updateTables, 500);