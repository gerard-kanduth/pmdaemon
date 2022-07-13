# Variable declaration
PROJECT_NAME=process_monitoring_daemon
COMPILER=g++
CFLAGS=-g -std=c++17 -pedantic -Wall -Wextra -Werror -Wshadow -Wconversion -Wunreachable-code
COMPILE=$(COMPILER) $(OPTIONS)
BUILD=build
LIBRARIES=-I include -lcurl
CPP_FILES=src/main.cpp src/settings.cpp src/rules.cpp src/logger.cpp src/controller.cpp

# Compile the main program
all: clean build $(PROJECT_NAME)

$(PROJECT_NAME):
	$(COMPILE) $(CPP_FILES) -o $(BUILD)/$(PROJECT_NAME) $(LIBRARIES)

# Create the build-folder
build:
	mkdir -p $(BUILD)

# Cleanup of previous builds and binary file
clean:
	rm -rf $(BUILD)
