# Global variables
PROJECT_NAME=process_monitoring_daemon
COMPILER=g++
ADVANCED_OPTIONS=-std=c++17 -pedantic -Wall -Wextra -Wshadow -Wconversion -Wunreachable-code
OPTIONS=-std=c++17
COMPILE=$(COMPILER) $(OPTIONS)
BUILD=build
LIBRARIES=-I include -lcurl
CPP_FILES=src/main.cpp src/settings.cpp src/rulemanager.cpp src/logger.cpp src/controller.cpp src/utils.cpp

# Compile the main program
all: clean build $(PROJECT_NAME)

# Compile the program with advanced compiler warnings
advanced: clean build
	$(COMPILER) $(ADVANCED_OPTIONS) $(CPP_FILES) -o $(BUILD)/$(PROJECT_NAME) $(LIBRARIES)

# Compile the main program with symbols for GDB debugging
debug: clean build
	$(COMPILE) -g $(CPP_FILES) -o $(BUILD)/$(PROJECT_NAME) $(LIBRARIES)
	gdb ./$(BUILD)/$(PROJECT_NAME)

# Compile only of the programm
$(PROJECT_NAME):
	$(COMPILE) $(CPP_FILES) -o $(BUILD)/$(PROJECT_NAME) $(LIBRARIES)

# Create the build-folder
build:
	mkdir -p $(BUILD)

# Cleanup of previous builds and binary file
clean:
	rm -rf $(BUILD)