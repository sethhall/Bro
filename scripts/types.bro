
module MQTT;

export {
	type MQTT::ConnectMsg: record {
		protocol_name    : string;
		protocol_version : count;
		client_id        : string;
		keep_alive       : count;

		will_retain      : bool;
		will_qos         : count;
		will_topic       : string &optional;
		will_msg         : string &optional;

		username         : string &optional;
		password         : string &optional;
	};
}
