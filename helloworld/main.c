int main()
{
	const char *str = "Hello World\n";
	//asm volatile("mov $0, %%rdi; mov %0, %%rsi; int $0x80"::"a"(str));
	while(1);
	return 0;
}
