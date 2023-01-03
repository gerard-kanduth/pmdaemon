# Global variables
PROJECT_NAME=pmdaemon
RPM_BUILD_ROOT=/srv/process_monitoring_daemon/build/rpmbuild
COMPILER=g++
ADVANCED_OPTIONS=-std=c++17 -pedantic -Wall -Wextra -Wshadow -Wconversion -Wunreachable-code
OPTIONS=-std=c++17
COMPILE=$(COMPILER) $(OPTIONS)
BUILD_DIR=build/usr/sbin
LIBRARIES=-I include -lcurl
CPP_FILES=src/main.cpp src/settings.cpp src/rulemanager.cpp src/logger.cpp src/controller.cpp src/utils.cpp

# Compile the main program and create a new RPM package
all: clean $(PROJECT_NAME) package

# Compile the program with advanced compiler warnings
advanced: clean
	$(COMPILER) $(ADVANCED_OPTIONS) $(CPP_FILES) -o $(BUILD_DIR)/$(PROJECT_NAME) $(LIBRARIES)

# Compile the main program with symbols and start GDB debugging
debug: clean
	$(COMPILE) -g $(CPP_FILES) -o $(BUILD_DIR)/$(PROJECT_NAME) $(LIBRARIES)
	gdb ./$(BUILD_DIR)/$(PROJECT_NAME)

# Compile the program
$(PROJECT_NAME):
	mkdir -p $(BUILD_DIR)
	$(COMPILE) $(CPP_FILES) -o $(BUILD_DIR)/$(PROJECT_NAME) $(LIBRARIES)

# Create a new RPM package but do not compile
package:
	mkdir -p $(RPM_BUILD_ROOT)
	rpmbuild --buildroot $(RPM_BUILD_ROOT) -ba $(PROJECT_NAME).spec

# Cleanup of previous builds and binary file
clean:
	rm -rf $(BUILD_DIR)
