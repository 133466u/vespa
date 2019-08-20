// Copyright 2019 Oath Inc. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#pragma once

#include "entry_comparator.h"
#include "unique_store_string_allocator.h"

namespace search::datastore {

/*
 * Compare two strings based on entry refs.  Valid entry ref is mapped
 * to a string in a data store.  Invalid entry ref is mapped to a
 * temporary string pointed to by comparator instance.
 */
template <typename RefT>
class UniqueStoreStringComparator : public EntryComparator {
    using RefType = RefT;
    using WrappedExternalEntryType = UniqueStoreEntry<std::string>;
    using DataStoreType = DataStoreT<RefT>;
    const DataStoreType &_store;
    const char *_value;
public:
    UniqueStoreStringComparator(const DataStoreType &store, const char *value)
        : _store(store),
          _value(value)
    {
    }
    const char *get(EntryRef ref) const {
        if (ref.valid()) {
            RefType iRef(ref);
            auto &state = _store.getBufferState(iRef.bufferId());
            auto type_id = state.getTypeId();
            if (type_id != 0) {
                return reinterpret_cast<const UniqueStoreSmallStringEntry *>(_store.template getEntryArray<char>(iRef, state.getArraySize()))->value();
            } else {
                return _store.template getEntry<WrappedExternalEntryType>(iRef)->value().c_str();
            }
        } else {
            return _value;
        }
    }

    bool operator()(const EntryRef lhs, const EntryRef rhs) const override
    {
        const char *lhs_value = get(lhs);
        const char *rhs_value = get(rhs);
        return (strcmp(lhs_value, rhs_value) < 0);
    }
};

}
