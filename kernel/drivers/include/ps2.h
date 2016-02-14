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
#ifndef PS2_H
#define PS2_H

#define PS2_STATUS 		0x64
#define PS2_COMMAND		0x64
#define PS2_DATA		0x60
#define PS2_RESET		0xFF
#define PS2_ACK			0xFA
#define PS2_INIT_OK		0x55
#define PS2_REINIT		0xAA
#define PS2_ECHO		0xEE
#define PS2_RESEND		0xFE
#define PS2_ST_FAILED		0xFC
#define PS2_ENABLE_SCANNING	0xF4
#define PS2_DISABLE_SCANNING	0xF5
#define PS2_TYPEMATIC_BYTE	0xF3
#define PS2_PORT_1_DISABLE	0xAD
#define PS2_PORT_2_DISABLE	0xA7
#define PS2_PORT_1_ENABLE	0xAE
#define PS2_PORT_2_ENABLE	0xA8
#define PS2_PORT_1_TEST		0xAB
#define PS2_PORT_2_TEST		0xA9



#endif // PS2_H
