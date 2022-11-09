#ifndef UTILS
#define UTILS

#include <iostream>
#include <filesystem>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include "logger.h"

namespace fs = std::filesystem;

class Utils {

	public:

		static bool checkIfFileExists(string);
		static bool checkIfDirectoryExists(string);
		static bool writeToFile(string, string);

};

#endif