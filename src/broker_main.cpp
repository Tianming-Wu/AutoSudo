/*
    Auto Sudo Broker Module

    This module acts as a bridge between the started program and the console that called AutoSudo.
    It is responsible for streaming the inputs and outputs.

    It is only meant to be started by the service.


    Call Protocol:
        AutoSudoBroker ["debug"] <assigned_pipe_name> <token>

    We do not do complex argument check.
*/



#include <SharedCppLib2/logt.hpp>
#include <SharedCppLib2/arguments.hpp>

#include <random>

#include "broker.hpp"

std::string generateStreamPipeName();

int main(int argc, char** argv) {
    std::stringlist args(argc, argv);
    args.erase(args.begin()); // Remove the program name

    if(args.empty()) return 0; // This program is not meant to be executed by the user. 

    LOGT_LOCAL("BrokerMain");
    logt::claim("BrokerMain");
    logt::addfile("autosudo_broker.log", true);

    if(args[0] == "debug") {
        // Will be the same as the service
        logt::setFilterLevel(LogLevel::Debug);
        args.erase(args.begin());
    }

    // args[0] -> assigned pipe name, args[1] -> token
    std::string inputStreamName = generateStreamPipeName();
    std::string outputStreamName = generateStreamPipeName();
    
    Broker broker(args[0], inputStreamName, outputStreamName, std::bytearray::fromHex(args[1]));

    auto result = broker.Run();
    
    logt::shutdown();
    return result;
}


// Generate a random pipe name.
std::string generateStreamPipeName() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);
    return R"(\\.\pipe\asb_)" + std::to_string(dis(gen));
}