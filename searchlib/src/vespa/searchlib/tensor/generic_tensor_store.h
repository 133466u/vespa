// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#pragma once

#include "tensor_store.h"

namespace search {

namespace tensor {

/**
 * Class for storing serialized tensors in memory, used by TensorAttribute.
 *
 * Serialization format is subject to change.  Changes to serialization format
 * might also require corresponding changes to implemented optimized tensor
 * operations that use the serialized tensor as argument.
 */
class GenericTensorStore : public TensorStore
{
public:
    using RefType = vespalib::datastore::AlignedEntryRefT<22, 2>;
    using DataStoreType = vespalib::datastore::DataStoreT<RefType>;
private:
    DataStoreType _concreteStore;
    vespalib::datastore::BufferType<char> _bufferType;
public:
    GenericTensorStore();

    virtual ~GenericTensorStore();

    std::pair<const void *, uint32_t> getRawBuffer(RefType ref) const;

    vespalib::datastore::Handle<char> allocRawBuffer(uint32_t size);

    virtual void holdTensor(EntryRef ref) override;

    virtual EntryRef move(EntryRef ref) override;

    std::unique_ptr<Tensor> getTensor(EntryRef ref) const;

    EntryRef setTensor(const Tensor &tensor);
};


}  // namespace search::tensor

}  // namespace search
