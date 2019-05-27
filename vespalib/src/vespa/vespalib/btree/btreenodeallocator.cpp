// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#include "btreenodeallocator.hpp"
#include <vespa/vespalib/util/array.hpp>

template class vespalib::Array<search::datastore::EntryRef>;

namespace search::btree {

template class BTreeNodeAllocator<uint32_t, uint32_t, NoAggregated,
                                  BTreeDefaultTraits::INTERNAL_SLOTS,
                                  BTreeDefaultTraits::LEAF_SLOTS>;
template class BTreeNodeAllocator<uint32_t, BTreeNoLeafData, NoAggregated,
                                  BTreeDefaultTraits::INTERNAL_SLOTS,
                                  BTreeDefaultTraits::LEAF_SLOTS>;
template class BTreeNodeAllocator<uint32_t, int32_t, MinMaxAggregated,
                                  BTreeDefaultTraits::INTERNAL_SLOTS,
                                  BTreeDefaultTraits::LEAF_SLOTS>;

}
