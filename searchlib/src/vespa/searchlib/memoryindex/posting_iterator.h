// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#pragma once

#include "field_index.h"
#include <vespa/searchlib/queryeval/iterators.h>

namespace search::memoryindex {

/**
 * Search iterator for memory field index posting list.
 *
 * The template parameter specifies whether the wrapped posting list has interleaved features or not.
 */
template <bool interleaved_features>
class PostingIterator : public queryeval::RankedSearchIteratorBase {
private:
    using FieldIndexType = FieldIndex<interleaved_features>;
    using PostingListIteratorType = typename FieldIndexType::PostingList::ConstIterator;
    PostingListIteratorType                            _itr;
    const FeatureStore                                &_featureStore;
    FeatureStore::DecodeContextCooked                  _featureDecoder;

public:
    /**
     * Creates a search iterator for the given posting list iterator.
     *
     * @param itr          the posting list iterator to base the search iterator upon.
     * @param featureStore reference to store for features.
     * @param packedIndex  the field or field collection owning features.
     * @param matchData    the match data to unpack features into.
     **/
    PostingIterator(PostingListIteratorType itr,
                    const FeatureStore &featureStore,
                    uint32_t packedIndex,
                    const fef::TermFieldMatchDataArray &matchData);
    ~PostingIterator();

    void doSeek(uint32_t docId) override;
    void doUnpack(uint32_t docId) override;
    void initRange(uint32_t begin, uint32_t end) override;
    Trinary is_strict() const override { return Trinary::True; }
};

}

