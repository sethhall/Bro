
#ifndef BRO_PLUGIN_BRO_MQTT
#define BRO_PLUGIN_BRO_MQTT

#include <plugin/Plugin.h>

namespace plugin {
namespace Bro_MQTT {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
