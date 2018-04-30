refine casetype Command += {
	MQTT_CONNACK -> connack : MQTT_connack;
};

type MQTT_connack = record {
	reserved    : uint8;
	return_code : uint8;
} &let {
	proc: bool = $context.flow.proc_mqtt_connack(this);
};

refine flow MQTT_Flow += {
	function proc_mqtt_connack(msg: MQTT_connack): bool
		%{
		if ( mqtt_connack )
			{
			BifEvent::generate_mqtt_connack(connection()->bro_analyzer(),
			                                connection()->bro_analyzer()->Conn(),
			                                ${msg.return_code});
			}

		return true;
		%}
};
