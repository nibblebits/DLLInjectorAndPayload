all:
	gcc  inject.c -o inject2.exe
	gcc  -shared -o PayloadDLL.dll payload.c