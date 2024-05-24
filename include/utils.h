#ifndef UTILS
#define UTILS

#include <iomanip>
#include <fstream>
#include <filesystem>
#include <regex>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include "logger.h"
#include "datatypes.h"

#ifndef POSDIFF
#define POSDIFF(a, b)   ((a) > (b) ? ((a) - (b)) : 0)
#endif

namespace fs = std::filesystem;
using namespace std;

class Utils {

	public:

        	static long total_ram;

        	static bool checkIfFileExists(string);
        	static bool checkIfDirectoryExists(string);
        	static bool writeToFile(string, string);
        	static bool isDisableValue(string*);
        	static bool isZeroOneValue(string*);
        	static bool isPercentValue(string*);
        	static bool isIntegerValue(string*);
        	static bool isCommaSepStringValue(string*);
        	static bool isFQDNValue(string*);
        	static bool isMemValue(string*);
        	static bool isAbsoluteMemValue(string*);
        	static CgroupCPUMax parseCPUMaxFile(string);
        	static double calcPercentCPU(unsigned long long*, unsigned long long*);
        	static int getActiveCoresCount(string*);
        	static long getTotalMemory();
        	static long long convertToBytes(string, string);
        	static ProcPIDStat parsePIDStatFile(int);
        	static ProcSysStat parseStatFile();
        	static string lowerText(string);
        	static string lowerText(char*);
        	static string readFromFile(string, bool);
        	static string readFromFile(string);
        	static string setToComSepString(set<string>);
        	static string generateJailMaxCPU(double);
        	static string generateMaxCPU(double, string);
        	static set<string> generateStringSet(string);        
        	static UptimeIdle getSystemUptime();

};

#endif
