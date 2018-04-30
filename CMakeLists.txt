
cmake_minimum_required(VERSION 2.8)

project(BroPluginMQTT)

include(BroPlugin)

bro_plugin_begin(Bro MQTT)
bro_plugin_cc(src/MQTT.cc src/Plugin.cc)
bro_plugin_bif(src/types.bif src/events.bif)
bro_plugin_pac(src/mqtt.pac  
               src/mqtt-protocol.pac
               src/mqtt-analyzer.pac
               src/commands/connect.pac
               src/commands/connack.pac
               src/commands/publish.pac
               src/commands/puback.pac
               src/commands/pubrec.pac
               src/commands/pubrel.pac
               src/commands/pubcomp.pac
               src/commands/subscribe.pac
               src/commands/suback.pac
               src/commands/unsuback.pac
               src/commands/unsubscribe.pac
               src/commands/disconnect.pac
               src/commands/pingreq.pac
               src/commands/pingresp.pac
               )


bro_plugin_dist_files(README CHANGES COPYING VERSION)
bro_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
