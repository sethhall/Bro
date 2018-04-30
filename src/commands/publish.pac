refine casetype Command += {
	MQTT_PUBLISH -> publish : MQTT_publish(pdu);
};

type MQTT_publish(pdu: MQTT_PDU) = record {
	topic   : MQTT_string;
	# If qos is zero, there won't be a msg_id field.
	has_msg_id: case qos of {
		0       -> none   : empty;
		default -> msg_id : uint16;
	};
	payload : bytestring &restofdata;
} &let {
	dup    : bool  = (pdu.fixed_header & 0x08) != 0;
	qos    : uint8 = (pdu.fixed_header & 0x06) >> 1;
	retain : bool  = (pdu.fixed_header & 0x01) != 0;

	proc: bool = $context.flow.proc_mqtt_publish(this, pdu);
};

refine flow MQTT_Flow += {
	function proc_mqtt_publish(msg: MQTT_publish, pdu: MQTT_PDU): bool
		%{
		if ( mqtt_publish )
			{
			auto topic = new StringVal(${msg.topic.str}.length(),
			                           (const char*) ${msg.topic.str}.begin());
			auto payload = new StringVal(${msg.payload}.length(),
			                             (const char*) ${msg.payload}.begin());

			BifEvent::generate_mqtt_publish(connection()->bro_analyzer(),
			                                connection()->bro_analyzer()->Conn(),
			                                ${pdu.is_orig},
			                                ${msg.qos} == 0 ? 0 : ${msg.msg_id},
			                                topic,
			                                payload);
			}

		// If a publish message was seen, let's say that confirms it.
		connection()->bro_analyzer()->ProtocolConfirmation();

		return true;
		%}
};
