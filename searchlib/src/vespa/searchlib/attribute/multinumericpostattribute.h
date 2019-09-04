// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#pragma once

#include "multinumericenumattribute.h"
#include "postinglistattribute.h"
#include "i_document_weight_attribute.h"

namespace search {

/**
 * Implementation of multi value numeric attribute that in addition to enum store and
 * multi value mapping uses an underlying posting list to provide faster search.
 * This class is used for both array and weighted set types.
 *
 * B: EnumAttribute<P, BaseClass>
 * M: multivalue::Value<IEnumStore::Index> (array) or
 *    multivalue::WeightedValue<IEnumStore::Index> (weighted set)
 * M specifies the type stored in the MultiValueMapping
 */
template <typename B, typename M>
class MultiValueNumericPostingAttribute
    : public MultiValueNumericEnumAttribute<B, M>,
      protected PostingListAttributeSubBase<AttributeWeightPosting,
                                            typename B::LoadedVector,
                                            typename B::LoadedValueType,
                                            typename B::EnumStore>
{
public:
    using EnumStore = typename B::EnumStore;
    using EnumIndex = typename EnumStore::Index;
    using EnumStoreBatchUpdater = typename EnumStore::BatchUpdater;

private:
    struct DocumentWeightAttributeAdapter : IDocumentWeightAttribute {
        const MultiValueNumericPostingAttribute &self;
        DocumentWeightAttributeAdapter(const MultiValueNumericPostingAttribute &self_in) : self(self_in) {}
        virtual LookupResult lookup(const vespalib::string &term) const override final;
        virtual void create(datastore::EntryRef idx, std::vector<DocumentWeightIterator> &dst) const override final;
        virtual DocumentWeightIterator create(datastore::EntryRef idx) const override final;
    };
    DocumentWeightAttributeAdapter _document_weight_attribute_adapter;

    friend class PostingListAttributeTest;
    template <typename, typename, typename> 
    friend class attribute::PostingSearchContext; // getEnumStore()

    using SelfType = MultiValueNumericPostingAttribute<B, M>;
    using LoadedVector = typename B::LoadedVector;
    using PostingParent = PostingListAttributeSubBase<AttributeWeightPosting, LoadedVector,
                                                      typename B::LoadedValueType, EnumStore>;

    using ArraySearchContext = typename MultiValueNumericEnumAttribute<B, M>::ArraySearchContext;
    using ArrayNumericSearchContext = ArraySearchContext;
    using ArrayPostingSearchContext = attribute::NumericPostingSearchContext<ArrayNumericSearchContext, SelfType, int32_t>;
    using ComparatorType = typename EnumStore::ComparatorType;
    using Dictionary = EnumPostingTree;
    using DictionaryConstIterator = typename Dictionary::ConstIterator;
    using DocId = typename B::DocId;
    using DocIndices = typename MultiValueNumericEnumAttribute<B, M>::DocIndices;
    using FrozenDictionary = typename Dictionary::FrozenView;
    using LoadedEnumAttributeVector = attribute::LoadedEnumAttributeVector;
    using Posting = typename PostingParent::Posting;
    using PostingList = typename PostingParent::PostingList;
    using PostingMap = typename PostingParent::PostingMap;
    using QueryTermSimpleUP = AttributeVector::QueryTermSimpleUP;
    using SetSearchContext = typename MultiValueNumericEnumAttribute<B, M>::SetSearchContext;
    using SetNumericSearchContext = SetSearchContext;
    using SetPostingSearchContext = attribute::NumericPostingSearchContext<SetNumericSearchContext, SelfType, int32_t>;
    using WeightedIndex = typename MultiValueNumericEnumAttribute<B, M>::WeightedIndex;
    using generation_t = typename MultiValueNumericEnumAttribute<B, M>::generation_t;

    using PostingParent::_postingList;
    using PostingParent::clearAllPostings;
    using PostingParent::handleFillPostings;
    using PostingParent::fillPostingsFixupEnumBase;
    using PostingParent::forwardedOnAddDoc;

    void freezeEnumDictionary() override;
    void mergeMemoryStats(vespalib::MemoryUsage & total) override;
    void applyValueChanges(const DocIndices& docIndices, EnumStoreBatchUpdater& updater) override;

public:
    MultiValueNumericPostingAttribute(const vespalib::string & name, const AttributeVector::Config & cfg);
    ~MultiValueNumericPostingAttribute();

    void removeOldGenerations(generation_t firstUsed) override;
    void onGenerationChange(generation_t generation) override;

    AttributeVector::SearchContext::UP
    getSearch(QueryTermSimpleUP term, const attribute::SearchContextParams & params) const override;

    const IDocumentWeightAttribute *asDocumentWeightAttribute() const override;

    bool onAddDoc(DocId doc) override {
        return forwardedOnAddDoc(doc, this->_mvMapping.getNumKeys(), this->_mvMapping.getCapacityKeys());
    }
    
    void fillPostings(LoadedVector & loaded) override {
        handleFillPostings(loaded);
    }

    attribute::IPostingListAttributeBase *getIPostingListAttributeBase() override {
        return this;
    }

    const attribute::IPostingListAttributeBase *getIPostingListAttributeBase() const override {
        return this;
    }

    void fillPostingsFixupEnum(enumstore::EnumeratedPostingsLoader& loader) override {
        fillPostingsFixupEnumBase(loader);
    }
};


} // namespace search

