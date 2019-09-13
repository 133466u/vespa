// Copyright 2019 Oath Inc. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#pragma once

#include "enum_store_loaders.h"
#include "enum_store_types.h"
#include <vespa/searchcommon/attribute/iattributevector.h>
#include <vespa/vespalib/datastore/entryref.h>
#include <vespa/vespalib/datastore/unique_store_enumerator.h>
#include <vespa/vespalib/stllike/hash_map.h>
#include <vespa/vespalib/util/array.h>
#include <vespa/vespalib/util/memoryusage.h>
#include <cassert>
#include <set>

namespace search {

namespace datastore {

class DataStoreBase;

template <typename> class UniqueStoreRemapper;

}

class BufferWriter;
class CompactionStrategy;
class IEnumStoreDictionary;

/**
 * Interface for an enum store that is independent of the data type stored.
 */
class IEnumStore {
public:
    using Index = enumstore::Index;
    using InternalIndex = enumstore::InternalIndex;
    using IndexVector = enumstore::IndexVector;
    using EnumHandle = enumstore::EnumHandle;
    using EnumVector = enumstore::EnumVector;
    using EnumIndexRemapper = datastore::UniqueStoreRemapper<InternalIndex>;
    using Enumerator = datastore::UniqueStoreEnumerator<IEnumStore::InternalIndex>;

    struct CompareEnumIndex {
        using Index = IEnumStore::Index;

        bool operator()(const Index &lhs, const Index &rhs) const {
            return lhs.ref() < rhs.ref();
        }
    };

    using IndexSet = std::set<Index, CompareEnumIndex>;

    virtual ~IEnumStore() = default;

    virtual void write_value(BufferWriter& writer, Index idx) const = 0;
    virtual ssize_t load_unique_values(const void* src, size_t available, IndexVector& idx) = 0;
    virtual void set_ref_count(Index idx, uint32_t ref_count) = 0;
    virtual void set_ref_counts(const EnumVector &histogram) = 0;
    virtual void free_value_if_unused(Index idx, IndexSet &unused) = 0;
    virtual void free_unused_values() = 0;
    virtual bool foldedChange(const Index& idx1, const Index& idx2) const = 0;
    virtual IEnumStoreDictionary& getEnumStoreDict() = 0;
    virtual const IEnumStoreDictionary& getEnumStoreDict() const = 0;
    virtual uint32_t getNumUniques() const = 0;
    virtual vespalib::MemoryUsage getValuesMemoryUsage() const = 0;
    virtual vespalib::MemoryUsage getDictionaryMemoryUsage() const = 0;
    virtual vespalib::MemoryUsage update_stat() = 0;
    virtual std::unique_ptr<EnumIndexRemapper> consider_compact(const CompactionStrategy& compaction_strategy) = 0;
    virtual std::unique_ptr<EnumIndexRemapper> compact_worst(bool compact_memory, bool compact_address_space) = 0;
    virtual uint64_t get_compaction_count() const = 0;
    // Should only be used by unit tests.
    virtual void inc_compaction_count() = 0;

    enumstore::EnumeratedLoader make_enumerated_loader() {
        return enumstore::EnumeratedLoader(*this);
    }

    enumstore::EnumeratedPostingsLoader make_enumerated_postings_loader() {
        return enumstore::EnumeratedPostingsLoader(*this);
    }

    virtual std::unique_ptr<Enumerator> make_enumerator() const = 0;

    template <typename TreeT>
    void set_ref_counts(const EnumVector& hist, TreeT& tree) {
        if (hist.empty()) {
            return;
        }
        typename TreeT::Iterator ti(tree.begin());
        typedef EnumVector::const_iterator HistIT;

        for (HistIT hi(hist.begin()), hie(hist.end()); hi != hie; ++hi, ++ti) {
            assert(ti.valid());
            set_ref_count(ti.getKey(), *hi);
        }
        assert(!ti.valid());
        free_unused_values();
    }
};

}
