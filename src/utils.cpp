#include "utils.h"

bool Utils::checkIfFileExists(string filename) {

	return ( access( filename.c_str(), F_OK ) != -1 );

}

bool Utils::checkIfDirectoryExists(string directory) {

	return fs::exists(directory.c_str());

}

bool Utils::writeToFile(string filename, string text) {

	FILE* file;

	file = fopen(filename.c_str(), "w");

    if (file) {
        fputs(text.c_str(), file);
    }
	else {
		Logger::logError("Unable to write to file "+filename+"!");
		return false;
	}

	fclose(file);
	return true;

}