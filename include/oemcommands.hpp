/*
// Copyright (c) 2018 Intel Corporation
// Copyright (c) 2022 Portwell Inc
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

#pragma once

#include <ipmid/api-types.hpp>
#include <user_channel/user_layer.hpp>
namespace ipmi
{
namespace pw
{
static constexpr NetFn netFnGeneral = netFnOemOne;

namespace general
{
static constexpr Cmd cmdSetBmcMac = 0x20;
static constexpr Cmd cmdGetBmcMac = 0x21;
} // namespace general

} // namespace pw

namespace intel
{

static constexpr NetFn netFnGeneral = netFnOemOne;
static constexpr NetFn netFnPlatform = netFnOemTwo;
static constexpr NetFn netFnApp = netFnOemEight;

namespace app
{
static constexpr Cmd cmdMdrStatus = 0x20;
static constexpr Cmd cmdMdrComplete = 0x21;
static constexpr Cmd cmdMdrEvent = 0x22;
static constexpr Cmd cmdMdrRead = 0x23;
static constexpr Cmd cmdMdrWrite = 0x24;
static constexpr Cmd cmdMdrLock = 0x25;
static constexpr Cmd cmdMdrIIAgentStatus = 0x30;
static constexpr Cmd cmdMdrIIGetDir = 0x31;
static constexpr Cmd cmdMdrIIGetDataInfo = 0x32;
static constexpr Cmd cmdMdrIILockData = 0x33;
static constexpr Cmd cmdMdrIIUnlockData = 0X34;
static constexpr Cmd cmdMdrIIGetDataBlock = 0x35;
static constexpr Cmd cmdMdrIISendDir = 0x38;
static constexpr Cmd cmdMdrIISendDataInfoOffer = 0x39;
static constexpr Cmd cmdMdrIISendDataInfo = 0x3a;
static constexpr Cmd cmdMdrIIDataStart = 0x3b;
static constexpr Cmd cmdMdrIIDataDone = 0x3c;
static constexpr Cmd cmdMdrIISendDataBlock = 0x3d;
static constexpr Cmd cmdSlotIpmb = 0x51;
} // namespace app

} // namespace intel

} // namespace ipmi

enum class IPMIPwOEMReturnCodes
{
    ipmiCCInvalidChecksum = 0x85,
};

enum class IPMINetfnIntelOEMAppCmd
{
    mdrStatus = 0x20,
    mdrComplete = 0x21,
    mdrEvent = 0x22,
    mdrRead = 0x23,
    mdrWrite = 0x24,
    mdrLock = 0x25,
    mdr2AgentStatus = 0x30,
    mdr2GetDir = 0x31,
    mdr2GetDataInfo = 0x32,
    mdr2LockData = 0x33,
    mdr2UnlockData = 0x34,
    mdr2GetDataBlock = 0x35,
    mdr2SendDir = 0x38,
    mdr2SendDataInfoOffer = 0x39,
    mdr2SendDataInfo = 0x3a,
    mdr2DataStart = 0x3b,
    mdr2DataDone = 0x3c,
    mdr2SendDataBlock = 0x3d,
};

#pragma pack(push, 1)
struct GUIDData
{
    uint8_t node1;
    uint8_t node2;
    uint8_t node3;
    uint8_t node4;
    uint8_t node5;
    uint8_t node6;
    uint8_t clock1;
    uint8_t clock2;
    uint8_t timeHigh1;
    uint8_t timeHigh2;
    uint8_t timeMid1;
    uint8_t timeMid2;
    uint8_t timeLow1;
    uint8_t timeLow2;
    uint8_t timeLow3;
    uint8_t timeLow4;
};
#pragma pack(pop)
