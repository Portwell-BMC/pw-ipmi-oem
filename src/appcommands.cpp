/*
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

#include <ipmid/api.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>

namespace ipmi
{

static void registerAPPFunctions() __attribute__((constructor));

static auto ipmiAppGetSelfTestResults() -> ipmi::RspType<uint8_t, uint8_t>
{
    // Byte 2:
    //  55h - No error.
    //  56h - Self Test function not implemented in this controller.
    //  57h - Corrupted or inaccesssible data or devices.
    //  58h - Fatal hardware error.
    //  FFh - reserved.
    //  all other: Device-specific 'internal failure'.
    //  Byte 3:
    //      For byte 2 = 55h, 56h, FFh:     00h
    //      For byte 2 = 58h, all other:    Device-specific
    //      For byte 2 = 57h:   self-test error bitfield.
    //      Note: returning 57h does not imply that all test were run.
    //      [7] 1b = Cannot access SEL device.
    //      [6] 1b = Cannot access SDR Repository.
    //      [5] 1b = Cannot access BMC FRU device.
    //      [4] 1b = IPMB signal lines do not respond.
    //      [3] 1b = SDR Repository empty.
    //      [2] 1b = Internal Use Area of BMC FRU corrupted.
    //      [1] 1b = controller update 'boot block' firmware corrupted.
    //      [0] 1b = controller operational firmware corrupted.
    constexpr uint8_t noError = 0x55;
    constexpr uint8_t zero = 0;
    return ipmi::responseSuccess(noError, zero);
}

static void registerAPPFunctions(void)
{
    // <Get Self Test Results>
    registerHandler(prioOpenBmcBase, netFnApp,
                    app::cmdGetSelfTestResults, Privilege::User, 
                    ipmiAppGetSelfTestResults);
}

} // namespace ipmi
