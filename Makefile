MAKEFLAGS= -s

PROJECT = Blackout

CCX64 = x86_64-w64-mingw32-g++

LDR = $(wildcard Loader/Source/*.cc)

all: agent-build extract clean loader-build

agent-build:
	@ echo "{+} Starting build agent..."
	@ cd Agent; cmake --build Build
	@ echo "{+} Agent build succefully!"

extract:
	@ echo "{+} Extracting shellcode from agent..."
	@ python3 Scripts/shellcode.py -f Bin/${PROJECT}.x64.exe -o Bin/${PROJECT}.x64.bin
	@ echo "{+} Shellcode extracted succefully!"

loader-build:
	@ echo "Starting build loader..."
	@ cmake --build Loader/Build
	@ echo "Loader build succefully!"

clean:
	@ echo "Cleaning all build..."
	@ rm -rf Agent/Build/*
	@ rm -rf Bin/*
	@ echo "Build cleaned!"