#include <windows.h>
#include <tchar.h>

int WINAPI WinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR lpCmdLine,
	int nCmdShow)
{
	MessageBox(NULL, TEXT("This is a Test\nBefore you press OK button, execute Injector.exe"), TEXT("Test"), MB_OK);
	MessageBox(NULL, TEXT("injection failed"), TEXT("Test"), MB_OK);
	return 0;
}