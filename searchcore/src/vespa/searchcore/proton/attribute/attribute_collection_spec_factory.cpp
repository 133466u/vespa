// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#include "attribute_collection_spec_factory.h"
#include <vespa/searchlib/attribute/configconverter.h>

using search::attribute::ConfigConverter;
using search::GrowStrategy;

namespace proton {

AttributeCollectionSpecFactory::AttributeCollectionSpecFactory(
        const search::GrowStrategy &growStrategy,
        size_t growNumDocs,
        const search::CompactionStrategy& compaction_strategy,
        bool fastAccessOnly)
    : _growStrategy(growStrategy),
      _growNumDocs(growNumDocs),
      _compaction_strategy(compaction_strategy),
      _fastAccessOnly(fastAccessOnly)
{
}

AttributeCollectionSpec::UP
AttributeCollectionSpecFactory::create(const AttributesConfig &attrCfg,
                                       uint32_t docIdLimit,
                                       search::SerialNum serialNum) const
{
    AttributeCollectionSpec::AttributeList attrs;
    // Amortize memory spike cost over N docs
    const size_t skew = _growNumDocs/(attrCfg.attribute.size()+1);
    GrowStrategy grow = _growStrategy;
    grow.setDocsInitialCapacity(std::max(grow.getDocsInitialCapacity(),docIdLimit));
    for (const auto &attr : attrCfg.attribute) {
        search::attribute::Config cfg = ConfigConverter::convert(attr);
        if (_fastAccessOnly && !cfg.fastAccess()) {
            continue;
        }
        grow.setDocsGrowDelta(grow.getDocsGrowDelta() + skew);
        cfg.setGrowStrategy(grow);
        cfg.setCompactionStrategy(_compaction_strategy);
        attrs.push_back(AttributeSpec(attr.name, cfg));
    }
    return std::make_unique<AttributeCollectionSpec>(attrs, docIdLimit, serialNum);
}

} // namespace proton
