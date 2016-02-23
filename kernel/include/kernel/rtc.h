/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#pragma once
#include <stdio.h>
#include <kernel/portio.h>

#define CMOS_ADDR 0x70
#define CMOS_DATA 0x71
typedef struct 
{
	uint8_t seconds;
	uint8_t minutes;
	uint8_t hours;
	uint8_t days;
	uint8_t months;
	uint8_t years;
	uint8_t centuries;
	uint8_t b_register;
}rtc_t;
namespace RTC
{
	void Init();
	rtc_t* ReadRTC();
	bool IsUpdateInProgress();
	uint8_t ReadRTCReg(int reg);
}
