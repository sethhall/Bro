
#include "Plugin.h"
#include "MQTT.h"

namespace plugin { namespace Bro_MQTT { Plugin plugin; } }

using namespace plugin::Bro_MQTT;

plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::analyzer::Component("MQTT",
	             ::analyzer::MQTT::MQTT_Analyzer::InstantiateAnalyzer));

	plugin::Configuration config;
	config.name = "Bro::MQTT";
	config.description = "Message Queuing Telemetry Transport Protocol analyzer";
	config.version.major = 0;
	config.version.minor = 1;
	return config;
	}
