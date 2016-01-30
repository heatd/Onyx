; Copyright 2016 Pedro Falcato
;
;Licensed under the Apache License, Version 2.0 (the "License");
;you may not use this file except in compliance with the License.
;You may obtain a copy of the License at
;
;http ://www.apache.org/licenses/LICENSE-2.0
;
;Unless required by applicable law or agreed to in writing, software
;distributed under the License is distributed on an "AS IS" BASIS,
;WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;See the License for the specific language governing permissions and
;limitations under the License.
;
section .init
global _init
_init:
	push ebp
	mov ebp,esp
	;gcc will nicely put the contents of crtbegin.o's .init section here.

section .fini
global _fini
_fini:
	push ebp
	mov ebp,esp
	;gcc will nicely put the contents of crtbegin.o's .fini section here.
