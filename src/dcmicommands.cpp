/*
// Copyright (c) 2022 Portwell Inc.
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

#include "dcmicommands.hpp"

#include "types.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <cstring>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>

using namespace phosphor::logging;

using Object = boost::container::flat_map<std::string, ipmi::DbusVariant>;
using ObjectType =
    boost::container::flat_map<std::string, Object>;
using ManagedObjectType =
    boost::container::flat_map<sdbusplus::message::object_path, ObjectType>;
using ManagedEntry = std::pair<sdbusplus::message::object_path, ObjectType>;

constexpr static const char* fruDeviceServiceName =
    "xyz.openbmc_project.FruDevice";
constexpr static const char* entityManagerServiceName =
    "xyz.openbmc_project.EntityManager";

static constexpr auto mapperBusName = "xyz.openbmc_project.ObjectMapper";
static constexpr auto mapperObjPath = "/xyz/openbmc_project/object_mapper";
static constexpr auto mapperIface = "xyz.openbmc_project.ObjectMapper";

static constexpr auto inventoryRoot = "/xyz/openbmc_project/inventory";
static constexpr auto fruRoot = "/xyz/openbmc_project/FruDevice";

static constexpr auto assetTagIface = "xyz.openbmc_project.FruDevice";
static constexpr auto assetTagProp = "PRODUCT_ASSET_TAG";

void registerDCMIFunctions() __attribute__((constructor));

namespace dcmi
{

ipmi_ret_t getBaseBoardFruPath(ipmi::Context::ptr ctx, std::string& fruPath)
{
    boost::system::error_code ec;

    ManagedObjectType entities = ctx->bus->yield_method_call<ManagedObjectType>(
        ctx->yield, ec, entityManagerServiceName, "/",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");

    if (ec)
    {
        log<level::ERR>("GetMangagedObjects for entity manager failed",
                        entry("ERROR=%s", ec.message().c_str()));

        return ipmi::ccResponseError;
    }

    ManagedObjectType frus = ctx->bus->yield_method_call<ManagedObjectType>(
        ctx->yield, ec, fruDeviceServiceName, "/",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");

    if (ec)
    {
        log<level::ERR>("GetMangagedObjects for fru device failed",
                        entry("ERROR=%s", ec.message().c_str()));

        return ipmi::ccResponseError;
    }

    uint8_t bus = 0, address = 0;

    auto entity = std::find_if(
        entities.begin(), entities.end(),
        [&bus, &address](ManagedEntry& entry) {
            auto findFruDevice = entry.second.find(
                "xyz.openbmc_project.Inventory.Item.System");
            if (findFruDevice == entry.second.end())
            {
                return false;
            }
            findFruDevice = entry.second.find(
                "xyz.openbmc_project.Inventory.Decorator.AssetTag");
            if (findFruDevice == entry.second.end())
            {
                return false;
            }
            findFruDevice = entry.second.find(
                "xyz.openbmc_project.Inventory.Decorator.I2CDevice");
            if (findFruDevice == entry.second.end())
            {
                return false;
            }

            // Integer fields added via Entity-Manager json are uint64_ts by
            // default.
            auto findBus = findFruDevice->second.find("Bus");
            auto findAddress = findFruDevice->second.find("Address");

            if (findBus == findFruDevice->second.end() ||
                findAddress == findFruDevice->second.end())
            {
                return false;
            }

            bus = std::get<uint64_t>(findBus->second);
            address = std::get<uint64_t>(findAddress->second);

            return true;
        });

    if (entity == entities.end())
    {
        log<level::WARNING>("Baseboard FRU is not found");
        return ipmi::ccResponseError;
    }

    auto fru = std::find_if(
        frus.begin(), frus.end(),
        [bus, address, &fruPath](ManagedEntry& entry) {
            auto findFruDevice = entry.second.find(
                "xyz.openbmc_project.FruDevice");
            if (findFruDevice == entry.second.end())
            {
                return false;
            }

            auto findBus = findFruDevice->second.find("BUS");
            auto findAddress = findFruDevice->second.find("ADDRESS");

            if (findBus == findFruDevice->second.end() ||
                findAddress == findFruDevice->second.end())
            {
                return false;
            }

            if ((std::get<uint32_t>(findBus->second) != bus) ||
                (std::get<uint32_t>(findAddress->second) != address))
            {
                return false;
            }

            fruPath = entry.first.str;

            return true;
        });

    if (fru == frus.end())
    {
        log<level::WARNING>("FruDevice not found for baseboard fru\n");
        return ipmi::ccResponseError;
    }

    log<level::DEBUG>("Found baseboard fru device\n");

    return ipmi::ccSuccess;
}

ipmi_ret_t readAssetTag(ipmi::Context::ptr ctx, std::string fruPath,
                        std::string& assetTag)
{
    boost::system::error_code ec;
    ec = ipmi::getDbusProperty(ctx, fruDeviceServiceName, fruPath,
                               assetTagIface, assetTagProp, assetTag);

    if (ec)
    {
        log<level::ERR>("Get AssetTag property failed",
                        entry("ERROR=%s", ec.message().c_str()));

        return ipmi::ccResponseError;
    }

    return ipmi::ccSuccess;
}

ipmi_ret_t writeAssetTag(ipmi::Context::ptr ctx, std::string fruPath,
                         std::string assetTag)
{
    boost::system::error_code ec;
    ec = ipmi::setDbusProperty(ctx, fruDeviceServiceName, fruPath,
                               assetTagIface, assetTagProp, assetTag);

    if (ec)
    {
        log<level::ERR>("Set AssetTag property failed",
                        entry("ERROR=%s", ec.message().c_str()));

        return ipmi::ccResponseError;
    }

    return ipmi::ccSuccess;
}

} // namespace dcmi

/** @brief implements the DCMI get asset tag command
 *  @param offset        - Offset to read
 *  @param bytes         - Number of bytes to read (16 bytes maximum)
 *
 *  @returns ipmi completion code plus response data
 *   - assetTagLength - Total Asset Tag Length
 *   - assetTagData   - Asset tag data (starting from offset to read)
 */
ipmi::RspType<uint8_t,             // total asset tag length
              std::vector<uint8_t> // asset tag data
              >
    ipmiGetAssetTag(ipmi::Context::ptr ctx, uint8_t offset, uint8_t bytes)
{
    // Verify offset to read and number of bytes to read are not exceeding the
    // range.
    if ((offset > dcmi::assetTagMaxOffset) || (bytes > dcmi::maxBytes) ||
        ((offset + bytes) > dcmi::assetTagMaxSize))
    {
        return ipmi::responseParmOutOfRange();
    }

    std::string fruPath;
    std::string assetTag;
    ipmi::Cc ret;

    ret = dcmi::getBaseBoardFruPath(ctx, fruPath);
    if (ret)
    {
        return ipmi::response(ret);
    }

    ret = dcmi::readAssetTag(ctx, fruPath, assetTag);
    if (ret)
    {
        return ipmi::response(ret);
    }

    // Return if the asset tag is not populated.
    if (!assetTag.size())
    {
        return ipmi::responseSuccess(0, std::vector<uint8_t>());
    }

    // If the asset tag is longer than 63 bytes, restrict it to 63 bytes to suit
    // Get Asset Tag command.
    if (assetTag.size() > dcmi::assetTagMaxSize)
    {
        assetTag.resize(dcmi::assetTagMaxSize);
    }

    // If the requested offset is beyond the asset tag size.
    if (offset >= assetTag.size())
    {
        return ipmi::responseParmOutOfRange();
    }

    uint8_t assetTagLength = assetTag.length();
    uint8_t countRead = bytes;
    if ((offset + bytes) > assetTagLength)
    {
        countRead = assetTagLength - offset;
    }

    std::vector<uint8_t> assetTagData(assetTag.begin() + offset,
                                      assetTag.begin() + offset + bytes);

    return ipmi::responseSuccess(assetTagLength, assetTagData);
}

/** @brief implements the DCMI set asset tag command
 *  @param offset        - Offset to write
 *  @param bytes         - Number of bytes to read (16 bytes maximum)
 *  @param dataToWrite   - Asset tag data
 *
 *  @returns ipmi completion code plus response data
 *   - assetTagLength - Total Asset Tag Length
 */
ipmi::RspType<uint8_t>  // total asset tag length
    ipmiSetAssetTag(ipmi::Context::ptr ctx, uint8_t offset,
                                       uint8_t bytes,
                                       std::vector<uint8_t>& dataToWrite)
{
    // Verify offset to read and number of bytes to read are not exceeding the
    // range.
    if ((offset > dcmi::assetTagMaxOffset) || (bytes > dcmi::maxBytes) ||
        ((offset + bytes) > dcmi::assetTagMaxSize))
    {
        return ipmi::responseParmOutOfRange();
    }

    if (bytes != dataToWrite.size())
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::string fruPath;
    std::string assetTag;
    ipmi::Cc ret;

    ret = dcmi::getBaseBoardFruPath(ctx, fruPath);
    if (ret)
    {
        return ipmi::response(ret);
    }

    std::string dataStr = std::string(dataToWrite.begin(), dataToWrite.end());
    uint8_t assetTagLength;

    if (offset == 0)
    {
        // If offset is zero, directly set the new asset tag data
        ret = dcmi::writeAssetTag(ctx, fruPath, dataStr);
        if (ret)
        {
            return ipmi::response(ret);
        }

        assetTagLength = bytes;
    }
    else
    {
        ret = dcmi::readAssetTag(ctx, fruPath, assetTag);
        if (ret)
        {
            return ipmi::response(ret);
        }

        assetTag.replace(offset, bytes, dataStr);
        assetTag.resize(offset + bytes);

        ret = dcmi::writeAssetTag(ctx, fruPath, assetTag);
        if (ret)
        {
            return ipmi::response(ret);
        }

        assetTagLength = offset + bytes;
    }

    return ipmi::responseSuccess(static_cast<uint8_t>(assetTagLength));
}

void registerDCMIFunctions()
{
    // <Get Asset Tag>
    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, dcmi::groupExtId,
                               ipmi::dcmi::cmdGetAssetTag,
                               ipmi::Privilege::Operator, ipmiGetAssetTag);

    // <Set Asset Tag>
    ipmi::registerGroupHandler(ipmi::prioOpenBmcBase, dcmi::groupExtId,
                               ipmi::dcmi::cmdSetAssetTag,
                               ipmi::Privilege::Operator, ipmiSetAssetTag);

    return;
}
