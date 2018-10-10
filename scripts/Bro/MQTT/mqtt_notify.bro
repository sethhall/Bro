##! This script detects mqtt control packet anomalies

@load base/frameworks/notice

module MQTT;

export {
	redef enum Notice::Type += { 
		## Raised when a connect packet has protocol version
		## other than 3 and 4. 
		Invalid_protocolVersion,

		## Raised when a connect packet has protocol version
		## other than 'MQTT' and 'MQIsdp'. 
		Invalid_protocolId,

		## Raised when a subscribe packet has QoS which is not 1 
		Wrong_subscribe_header,
		};
}

event mqtt_connect(c: connection, data: MQTT::ConnectMsg)
	{
	if ( data$protocol_version != 3 && data$protocol_version != 4 )
		{
		NOTICE([$note=Invalid_protocolVersion,
		        $msg=fmt("%d is not a valid protocol version.", data$protocol_version),
		        $conn=c]);
		}
	
	if ( data$protocol_name != "MQTT" && data$protocol_name != "MQIsdp")
		{
		NOTICE([$note=Invalid_protocolId,
		        $msg=fmt("%d is not a valid protocol version.", data$protocol_name),
		        $conn=c]);
		}
	}

event mqtt_subscribe(c: connection, msg_id: count, topic: string, requested_qos: count)
	{
	if ( requested_qos != 1 )
		{
		NOTICE([$note=Wrong_subscribe_header,
		        $msg=fmt("%d is an invalid QoS to be requested.", requested_qos),
		        $conn=c]);
		}
}
