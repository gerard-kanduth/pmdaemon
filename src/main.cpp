#include <csignal>
#include <iostream>
#include <string>
#include <stdlib.h>
#include <unistd.h>
#include "controller.h"
#include "logger.h"
#include "settings.h"
#include "utils.h"

using namespace std;

// logger instance (singleton-class)
Logger *logger = nullptr;

// controller-object
Controller* controller = nullptr;

// settings object (contains all settings)
Settings* settings = nullptr;

// boolean which defines if daemon is running
bool running = true;

// check-interval value (wait-time)
int check_interval;

// signal handler (needed to remove all created cgroups and for debug purpose)
void signalHandler(int signal) {

    switch(signal)  {

        // SIGTERM signal
        case 15:
           running = false;
            break;

        // SIGABRT signal
        case 6:
           running = false;
            break;

        // SIGUSR1 signal
        case 10:
            controller->cleanupCgroups(false);
            break;

        // SIGUSR2 signal
        case 12:
            controller->showInformation(true);
            break;

        // unknown signals
        default:
            cerr << DAEMON_NAME << " received unknown signal (" << to_string(signal) << ")!";
            break;

    }

}

// main, this is where all the magic happens
int main() {

    // register all needed signals to the signal handler
    signal(SIGTERM, signalHandler);
    signal(SIGABRT, signalHandler);
    signal(SIGUSR1, signalHandler);
    signal(SIGUSR2, signalHandler);

    // initialize a singleton instance for the logger
    logger = Logger::getInstance();

    // load the configuration file
    settings = Settings::getInstance();

    // terminate if configuration is broken or not available
    if (!settings->configAvailable()){
        logger->logError("Unable to load configuration! Stopping!");
        return 1;
    }

    // set the loglevel for the Logger
    logger->setLogLevel(settings->getLogLevel(), settings->getDebugLevel());

    // set settings defined in settings-file
    check_interval = settings->getCheckInterval();

    // initializing the controller
    controller = new Controller();

    /* --- start check routine --- */
    logger->logNotice("Starting " DAEMON_NAME " monitoring");
    while(running) {

        // run a check-cycle (exit if too many faulty checks)
        if (controller->doCheck() == false) return 1;

        // wait before next check
        sleep(check_interval);
    }
    /* --- end check routine --- */

    if (controller->controllerShutdown()) return 0;
    else return 1;

}
