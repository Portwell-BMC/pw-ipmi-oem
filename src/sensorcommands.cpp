/*
// Copyright (c) 2017 2018 Intel Corporation
// Copyright (c) 2021 Portwell Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

//#include "sensorcommands.hpp"

#include "commandutils.hpp"
#include "ipmi_to_redfish_hooks.hpp"
#include "sdrutils.hpp"
#include "types.hpp"

#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-ipmi-host/sensorhandler.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>

#include <cstring>

using namespace phosphor::logging;

namespace ipmi
{

void registerSensorFunctions() __attribute__((constructor));

static inline std::string toHex(uint8_t byte)
{
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << std::setfill('0')
       << std::setw(2) << static_cast<int>(byte);
    return ss.str();
}

ipmi::RspType<> ipmiSenPlatformEvent(ipmi::Context::ptr ctx,
                                     ipmi::message::Payload& p)
{
    uint8_t sysgeneratorID = 0;
    uint8_t evmRev = 0;
    uint8_t sensorType = 0;
    uint8_t sensorNum = 0;
    uint8_t eventType = 0;
    uint8_t eventData1 = 0;
    std::optional<uint8_t> eventData2 = 0;
    std::optional<uint8_t> eventData3 = 0;
    uint16_t generatorID = 0;
    bool assert = true;
    std::string sensorPath;
    ipmi::ChannelInfo chInfo;

    if (ipmi::getChannelInfo(ctx->channel, chInfo) != ipmi::ccSuccess)
    {
        log<level::ERR>("Failed to get Channel Info",
                        entry("CHANNEL=%d", ctx->channel));
        return ipmi::responseUnspecifiedError();
    }

    if (static_cast<ipmi::EChannelMediumType>(chInfo.mediumType) ==
        ipmi::EChannelMediumType::systemInterface)
    {

        p.unpack(sysgeneratorID, evmRev, sensorType, sensorNum, eventType,
                 eventData1, eventData2, eventData3);
        constexpr const uint8_t isSoftwareID = 0x01;
        if (!(sysgeneratorID & isSoftwareID))
        {
            return ipmi::responseInvalidFieldRequest();
        }
        // Refer to IPMI Spec Table 32: SEL Event Records
        generatorID = (ctx->channel << 12) // Channel
                      | (0x0 << 10)        // Reserved
                      | (0x0 << 8)         // 0x0 for sys-soft ID
                      | sysgeneratorID;
        sensorPath = "PE_System";
    }
    else
    {

        p.unpack(evmRev, sensorType, sensorNum, eventType, eventData1,
                 eventData2, eventData3);
        // Refer to IPMI Spec Table 32: SEL Event Records
        generatorID = (ctx->channel << 12)      // Channel
                      | (0x0 << 10)             // Reserved
                      | ((ctx->lun & 0x3) << 8) // Lun
                      | (ctx->rqSA << 1);
        
        if (static_cast<ipmi::EChannelMediumType>(chInfo.mediumType) ==
            ipmi::EChannelMediumType::oem)
        {
            sensorPath = "PE_Self";
        }
        else
        {
            sensorPath = "PE_Ipmb";
        }
    }

    if (!p.fullyUnpacked())
    {
        return ipmi::responseReqDataLenInvalid();
    }

    // Check for valid evmRev and Sensor Type(per Table 42 of spec)
    if (evmRev != 0x04)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    if ((sensorType > 0x2C) && (sensorType < 0xC0))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    assert = eventType & directionMask ? false : true;
    p.reset();
    const auto& [vb, ve] = p.pop<uint8_t>(p.size());
    std::vector<uint8_t> eventData(vb, ve);

    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    std::string service =
        ipmi::getService(*bus, ipmiSELAddInterface, ipmiSELPath);
    sdbusplus::message::message writeSEL = bus->new_method_call(
        service.c_str(), ipmiSELPath, ipmiSELAddInterface, "IpmiSelAdd");
    writeSEL.append(ipmiSELAddMessage, sensorPath, eventData, assert,
                    generatorID);
    try
    {
        bus->call(writeSEL);
    }
    catch (const sdbusplus::exception_t& e)
    {
        log<level::ERR>(e.what());
        return ipmi::responseResponseError();
    }

    // Send this request to the Redfish hooks to log it as a Redfish message
    // instead.  There is no need to add it to the SEL, so just return success.
    pw_oem::ipmi::sel::checkRedfishHooks(
        generatorID, evmRev, sensorType, sensorNum, eventType, eventData1,
        eventData2.value_or(0xFF), eventData3.value_or(0xFF));

    return ipmi::responseSuccess();
}

void registerSensorFunctions()
{
    // <Platform Event>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdPlatformEvent,
                          ipmi::Privilege::Operator, ipmiSenPlatformEvent);
}
} // namespace ipmi
