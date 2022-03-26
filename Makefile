# Variable declaration
PROJECT_NAME=process_monitoring_daemon
COMPILER=g++
CFLAGS=-g -std=c++17 -pedantic -Wall -Wextra -Werror -Wshadow -Wconversion -Wunreachable-code
COMPILE=$(COMPILER) $(OPTIONS)
BUILD=build
LIBRARIES=

# Compile the main program
all: $(PROJECT_NAME)

$(PROJECT_NAME):
	$(COMPILE) src/main.cpp -o $(BUILD)/$(PROJECT_NAME) $(LIBRARIES)

# Create the build-folder
build:
	mkdir -p $(BUILD)

# Cleanup of previous buildsi and binary file
clean:
	rm -rf $(BUILD)
