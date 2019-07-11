// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#include "dense_tensor_attribute.h"
#include "dense_tensor_attribute_saver.h"
#include "tensor_attribute.hpp"
#include <vespa/eval/tensor/tensor.h>
#include <vespa/eval/tensor/dense/mutable_dense_tensor_view.h>
#include <vespa/fastlib/io/bufferedfile.h>
#include <vespa/searchlib/attribute/readerbase.h>

#include <vespa/log/log.h>
LOG_SETUP(".searchlib.tensor.dense_tensor_attribute");

using vespalib::eval::ValueType;
using vespalib::tensor::MutableDenseTensorView;
using vespalib::tensor::Tensor;

namespace search::tensor {

namespace {

constexpr uint32_t DENSE_TENSOR_ATTRIBUTE_VERSION = 1;
const vespalib::string tensorTypeTag("tensortype");

class TensorReader : public ReaderBase
{
private:
    static constexpr uint8_t tensorIsNotPresent = 0;
    static constexpr uint8_t tensorIsPresent = 1;
public:
    TensorReader(AttributeVector &attr);
    ~TensorReader();
    bool is_present();
    void readTensor(void *buf, size_t len) { _datFile->ReadBuf(buf, len); }
};

TensorReader::TensorReader(AttributeVector &attr)
    : ReaderBase(attr)
{
}
TensorReader::~TensorReader() = default;

bool
TensorReader::is_present() {
    unsigned char detect;
    _datFile->ReadBuf(&detect, sizeof(detect));
    if (detect == tensorIsNotPresent) {
        return false;
    }
    if (detect != tensorIsPresent) {
        LOG_ABORT("should not be reached");
    }
    return true;
}

}

DenseTensorAttribute::DenseTensorAttribute(vespalib::stringref baseFileName,
                                 const Config &cfg)
    : TensorAttribute(baseFileName, cfg, _denseTensorStore),
      _denseTensorStore(cfg.tensorType())
{
}


DenseTensorAttribute::~DenseTensorAttribute()
{
    getGenerationHolder().clearHoldLists();
    _tensorStore.clearHoldLists();
}

void
DenseTensorAttribute::setTensor(DocId docId, const Tensor &tensor)
{
    checkTensorType(tensor);
    EntryRef ref = _denseTensorStore.setTensor(tensor);
    setTensorRef(docId, ref);
}


std::unique_ptr<Tensor>
DenseTensorAttribute::getTensor(DocId docId) const
{
    EntryRef ref;
    if (docId < getCommittedDocIdLimit()) {
        ref = _refVector[docId];
    }
    if (!ref.valid()) {
        return std::unique_ptr<Tensor>();
    }
    return _denseTensorStore.getTensor(ref);
}

void
DenseTensorAttribute::getTensor(DocId docId, MutableDenseTensorView &tensor) const
{
    EntryRef ref;
    if (docId < getCommittedDocIdLimit()) {
        ref = _refVector[docId];
    }
    _denseTensorStore.getTensor(ref, tensor);
}

bool
DenseTensorAttribute::onLoad()
{
    TensorReader tensorReader(*this);
    if (!tensorReader.hasData()) {
        return false;
    }
    setCreateSerialNum(tensorReader.getCreateSerialNum());
    assert(tensorReader.getVersion() == DENSE_TENSOR_ATTRIBUTE_VERSION);
    assert(getConfig().tensorType().to_spec() ==
           tensorReader.getDatHeader().getTag(tensorTypeTag).asString());
    uint32_t numDocs(tensorReader.getDocIdLimit());
    _refVector.reset();
    _refVector.unsafe_reserve(numDocs);
    for (uint32_t lid = 0; lid < numDocs; ++lid) {
        if (tensorReader.is_present()) {
            auto raw = _denseTensorStore.allocRawBuffer();
            tensorReader.readTensor(raw.data, _denseTensorStore.getBufSize());
            _refVector.push_back(raw.ref);
        } else {
            _refVector.push_back(EntryRef());
        }
    }
    setNumDocs(numDocs);
    setCommittedDocIdLimit(numDocs);
    return true;
}


std::unique_ptr<AttributeSaver>
DenseTensorAttribute::onInitSave(vespalib::stringref fileName)
{
    vespalib::GenerationHandler::Guard guard(getGenerationHandler().
                                             takeGuard());
    return std::make_unique<DenseTensorAttributeSaver>
        (std::move(guard),
         this->createAttributeHeader(fileName),
         getRefCopy(),
         _denseTensorStore);
}

void
DenseTensorAttribute::compactWorst()
{
    doCompactWorst<DenseTensorStore::RefType>();
}

uint32_t
DenseTensorAttribute::getVersion() const
{
    return DENSE_TENSOR_ATTRIBUTE_VERSION;
}

}
