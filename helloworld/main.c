int main()
{
	const char *str = "Hello World\n";
	asm volatile("mov $4, %%rdi; mov $1, %%rsi; mov %0, %%rdx; mov $12, %%rcx; int $0x80"::"a"(str));
	while(1);
	return 0;
}
