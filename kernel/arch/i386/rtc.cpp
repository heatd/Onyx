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
#include <kernel/rtc.h>
#include <kernel/nmi.h>
#include <kernel/irq.h>
#include <stdio.h>
static rtc_t* current_time;
static void IRQ8handler()
{
	current_time = RTC::ReadRTC();
	//If we don't read this,an interrupt will never happen again
	outb(CMOS_ADDR,0x0C);
	inb(CMOS_DATA);
}
namespace RTC
{	
	//Initializes the RTC (Real time clock)
	void Init()
	{	//Disable all interrupts and NMI's
		//This is very important, because an interrupt might occur
		//and if it does,the CMOS can be left in a bad state
		//and as the CMOS isn't initialized by the BIOS and runs on a separate battery,
		//It won't be reset by a reboot
		asm volatile("cli");
		
		//Disable NMI's (Non-maskable interrupts)
		NMI::Disable();
		
		uint8_t b = inb(CMOS_DATA);
		outb(CMOS_ADDR,0x8B);
		io_wait();
		outb(CMOS_DATA, b | 0x40); // enable the IRQ8 interrupts
		b = inb(CMOS_DATA);
		outb(CMOS_ADDR,0x8B);
		io_wait();
		outb(CMOS_DATA, b | 4); // enable the 24 hour format
		//Map IRQ8
		irq_t irq = IRQ8handler;
		IRQ::InstallHandler(8,IRQ8handler);
		
		//Re-enable them
		NMI::Enable();
		asm volatile("sti");
	}
	uint8_t ReadRTCReg(int reg)
	{
		outb(CMOS_ADDR,reg);
		io_wait();
		return (inb(CMOS_DATA) & 0x80);
	}
	bool IsUpdateInProgress()
	{
		return ReadRTCReg(0x0A) & 0x80;
	}
	rtc_t* ReadRTC()
	{
		while(IsUpdateInProgress());
		rtc_t rtc;
		rtc.seconds = ReadRTCReg(0);
		rtc.minutes = ReadRTCReg(0x02);
		rtc.hours = ReadRTCReg(0x04);
		rtc.days = ReadRTCReg(0x07);
		rtc.months = ReadRTCReg(0x08);
		rtc.years = ReadRTCReg(0x09);
		rtc.centuries = ReadRTCReg(0x32);
		rtc.b_register = ReadRTCReg(0x0B);
		return &rtc;
	}
}
