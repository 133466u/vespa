// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
#include "timestamp.h"
#include <chrono>
#include <cmath>
#include <sys/time.h>

using namespace std::chrono;

namespace fastos {

const TimeStamp::TimeT TimeStamp::MILLI;
const TimeStamp::TimeT TimeStamp::MICRO;
const TimeStamp::TimeT TimeStamp::NANO;
const TimeStamp::TimeT TimeStamp::US;
const TimeStamp::TimeT TimeStamp::MS;
const TimeStamp::TimeT TimeStamp::SEC;
const TimeStamp::TimeT TimeStamp::MINUTE;

std::string
TimeStamp::asString(double timeInSeconds)
{
    double intpart;
    double fractpart = std::modf(timeInSeconds, &intpart);
    time_t timeStamp = (time_t)intpart;
    struct tm timeStruct;
    gmtime_r(&timeStamp, &timeStruct);
    char timeString[128];
    strftime(timeString, sizeof(timeString), "%F %T", &timeStruct);
    char retval[160];
    uint32_t milliSeconds = std::min((uint32_t)(fractpart * 1000.0), 999u);
    snprintf(retval, sizeof(retval), "%s.%03u UTC", timeString, milliSeconds);
    return std::string(retval);
}

int64_t
ClockSystem::now()
{
    struct timeval timeNow;
    gettimeofday(&timeNow, nullptr);
    int64_t ns = timeNow.tv_sec;
    ns *= TimeStamp::NANO;
    ns += timeNow.tv_usec*1000;
    return ns;
}

time_t
time() {
    return system_clock::to_time_t(system_clock::now());
}

namespace {

int64_t
steady_now() {
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}

}

int64_t
ClockSteady::now()
{
    return steady_now();
}

StopWatch &
StopWatch::start() {
    _startTime = steady_now();
    _stopTime = _startTime;
    return *this;
}

StopWatch &
StopWatch::stop()  {
    _stopTime = steady_now();
    return *this;
}

}
