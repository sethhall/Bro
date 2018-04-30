##! Implements base functionality for MQTT analysis.
##! Generates the mqtt.log file.

module MQTT;

@load ./consts.bro

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts:     time    &log;
		## Unique ID for the connection.
		uid:    string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:     conn_id &log;

		msg_type: string &log;

		pname:  string  &log;

		pversion: count &log;

		cid: string &log;
		
		return_code: string &log;

		msg_id: count &log;

		topic: string &log;

		qos: count &log;
	};

	## Event that can be handled to access the MQTT record as it is sent on
	## to the logging framework.
	global log_mqtt: event(rec: Info);
}

const ports = { 1883/tcp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(MQTT::LOG, [$columns=Info, $ev=log_mqtt, $path="mqtt"]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_MQTT, ports);
	}

event mqtt_connect(c: connection, msg: MQTT::ConnectMsg) &priority=5
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$msg_type = "connect";
	info$pname = msg$protocol_name;
	info$pversion = msg$protocol_version;
	info$cid = msg$client_id;

	Log::write(MQTT::LOG, info);
	}

event mqtt_connack(c: connection, return_code: count) &priority=5
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$msg_type = "connack";
	info$return_code = return_codes[return_code];

	Log::write(MQTT::LOG, info);
	}

event mqtt_publish(c: connection, is_orig: bool, msg_id: count, topic: string, payload: string) &priority=5
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$msg_type = "publish";
	info$msg_id = msg_id;
	info$topic = topic;

	Log::write(MQTT::LOG, info);
	}

event mqtt_puback(c: connection, is_orig: bool, msg_id: count) &priority=5
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$msg_type = "puback";
	info$msg_id = msg_id;

	Log::write(MQTT::LOG, info);
	}

event mqtt_pubrec(c: connection, is_orig: bool, msg_id: count) &priority=5
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$msg_type = "pubrec";
	info$msg_id = msg_id;

	Log::write(MQTT::LOG, info);
	}

event mqtt_pubrel(c: connection, is_orig: bool, msg_id: count) &priority=5
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$msg_type = "pubrel";
	info$msg_id = msg_id;

	Log::write(MQTT::LOG, info);
	}

event mqtt_pubcomp(c: connection, is_orig: bool, msg_id: count) &priority=5
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$msg_type = "pubcomp";
	info$msg_id = msg_id;

	Log::write(MQTT::LOG, info);
	}


event mqtt_subscribe(c: connection, msg_id: count, topic: string, requested_qos: count) &priority=5
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$msg_type = "subscribe";
	info$msg_id = msg_id;
	info$topic = topic;
	info$qos = requested_qos;

	Log::write(MQTT::LOG, info);
	}

event mqtt_suback(c: connection, msg_id: count, granted_qos: count) &priority=5
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$msg_type = "suback";
	info$msg_id = msg_id;
	info$qos = granted_qos;

	Log::write(MQTT::LOG, info);
	}

event mqtt_unsubscribe(c: connection, msg_id: count, topic: string) &priority=5
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$msg_type = "unsubscribe";
	info$msg_id = msg_id;
	info$topic = topic;

	Log::write(MQTT::LOG, info);
	}

event mqtt_unsuback(c: connection, msg_id: count) &priority=5
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$msg_type = "unsuback";
	info$msg_id = msg_id;

	Log::write(MQTT::LOG, info);
	}

event mqtt_pingreq(c: connection) &priority=5
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$msg_type = "pingreq";

	Log::write(MQTT::LOG, info);
	}

event mqtt_pingresp(c: connection) &priority=5
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$msg_type = "pingresp";

	Log::write(MQTT::LOG, info);
	}

event mqtt_disconnect(c: connection) &priority=5
	{
	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$msg_type = "disconnect";

	Log::write(MQTT::LOG, info);
	}

