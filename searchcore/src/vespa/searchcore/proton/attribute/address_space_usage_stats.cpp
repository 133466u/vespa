// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#include "address_space_usage_stats.h"

namespace proton {

AddressSpaceUsageStats::AddressSpaceUsageStats(const vespalib::AddressSpace & usage)
    : _usage(usage),
      _attributeName(),
      _subDbName()
{
}

AddressSpaceUsageStats::~AddressSpaceUsageStats() = default;

void
AddressSpaceUsageStats::merge(const vespalib::AddressSpace &usage,
                              const vespalib::string &attributeName,
                              const vespalib::string &subDbName)
{
    if (attributeName.empty() || usage.usage() > _usage.usage()) {
        _usage = usage;
        _attributeName = attributeName;
        _subDbName = subDbName;
    }
}

} // namespace proton
