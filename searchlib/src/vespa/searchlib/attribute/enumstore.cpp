// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#include "enumstore.hpp"
#include <iomanip>

#include <vespa/log/log.h>
LOG_SETUP(".searchlib.attribute.enum_store");

namespace search {

template <>
void
EnumStoreT<StringEntryType>::
insertEntryValue(char * dst, Type value)
{
    strcpy(dst, value);
}

template <>
void
EnumStoreT<StringEntryType>::writeValues(BufferWriter &writer,
                                         const Index *idxs,
                                         size_t count) const
{
    for (uint32_t i = 0; i < count; ++i) {
        Index idx = idxs[i];
        const char *src(_store.getEntry<char>(idx) +
                        EntryBase::size());
        size_t sz = strlen(src) + 1;
        writer.write(src, sz);
    }
}


template <>
ssize_t
EnumStoreT<StringEntryType>::deserialize(const void *src,
                                            size_t available,
                                            size_t &initSpace)
{
    size_t slen = strlen(static_cast<const char *>(src));
    size_t sz(StringEntryType::fixedSize() + slen);
    if (available < sz)
        return -1;
    uint32_t entrySize(alignEntrySize(EntryBase::size() + sz));
    initSpace += entrySize;
    return sz;
}


template <>
ssize_t
EnumStoreT<StringEntryType>::deserialize(const void *src,
                                            size_t available,
                                            Index &idx)
{
    size_t slen = strlen(static_cast<const char *>(src));
    size_t sz(StringEntryType::fixedSize() + slen);
    if (available < sz)
        return -1;
    uint32_t activeBufferId = _store.getActiveBufferId(TYPE_ID);
    datastore::BufferState & buffer = _store.getBufferState(activeBufferId);
    uint32_t entrySize(alignEntrySize(EntryBase::size() + sz));
    if (buffer.remaining() < entrySize) {
        LOG_ABORT("Out of enumstore bufferspace");
    }
    uint64_t offset = buffer.size();
    Index newIdx(offset, activeBufferId);
    char *dst(_store.getEntry<char>(newIdx));
    memcpy(dst, &_nextEnum, sizeof(uint32_t));
    uint32_t pos = sizeof(uint32_t);
    uint32_t refCount(0);
    memcpy(dst + pos, &refCount, sizeof(uint32_t));
    pos += sizeof(uint32_t);
    memcpy(dst + pos, src, sz);
    buffer.pushed_back(entrySize);
    ++_nextEnum;

    if (idx.valid()) {
        assert(ComparatorType::compare(getValue(idx), Entry(dst).getValue()) < 0);
    }
    idx = newIdx;
    return sz;
}

template
class btree::BTreeBuilder<EnumStoreBase::Index, btree::BTreeNoLeafData, btree::NoAggregated,
                          EnumTreeTraits::INTERNAL_SLOTS, EnumTreeTraits::LEAF_SLOTS>;

template
class btree::BTreeBuilder<EnumStoreBase::Index, datastore::EntryRef, btree::NoAggregated,
                          EnumTreeTraits::INTERNAL_SLOTS, EnumTreeTraits::LEAF_SLOTS>;

template class EnumStoreT< StringEntryType >;
template class EnumStoreT<NumericEntryType<int8_t> >;
template class EnumStoreT<NumericEntryType<int16_t> >;
template class EnumStoreT<NumericEntryType<int32_t> >;
template class EnumStoreT<NumericEntryType<int64_t> >;
template class EnumStoreT<NumericEntryType<float> >;
template class EnumStoreT<NumericEntryType<double> >;

} // namespace search
