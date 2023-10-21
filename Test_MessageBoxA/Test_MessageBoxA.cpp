#include<windows.h>

int main() {
	MessageBoxA(NULL, "TestMessageBox", "notice", MB_OK);
	Sleep(3000);
	MessageBoxA(NULL, "TestMessageBox1", "notice", MB_OK);
	return 0;
}