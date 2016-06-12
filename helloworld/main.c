



int main()
{
	asm volatile("mov %rax, (0xDEADBEEEF)\t\n");
	while(1);
	return 0;
}
