// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#pragma once

#include <vespa/vespalib/btree/btree_key_data.h>

namespace search {

using AttributePosting = btree::BTreeKeyData<uint32_t, btree::BTreeNoLeafData>;
using AttributeWeightPosting = btree::BTreeKeyData<uint32_t, int32_t>;

}

