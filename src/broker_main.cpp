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

#include "broker.hpp"

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

    std::wstring assigned_pipe_name = platform::stringToWstring(args[0]);
    std::string token = args[1];


    Broker broker;

    return broker.Start(assigned_pipe_name, std::bytearray::fromHex(token));
}