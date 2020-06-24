// Copyright Verizon Media. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#include <vespa/vespalib/testkit/testapp.h>
#include <vespa/searchlib/queryeval/filter_wrapper.h>
#include <vespa/searchlib/fef/termfieldmatchdata.h>
#include <vespa/searchlib/common/bitvectoriterator.h>
#include <vespa/searchlib/test/searchiteratorverifier.h>

using namespace search::fef;
using namespace search::queryeval;
using search::BitVector;
using search::BitVectorIterator;

struct DummyItr : public SearchIterator {
    static uint32_t seekCnt;
    static uint32_t unpackCnt;
    static uint32_t dtorCnt;
    static uint32_t _unpackedDocId;
    TermFieldMatchData *match;

    DummyItr(TermFieldMatchData *m) {
        match = m;
    }

    ~DummyItr() {
        ++dtorCnt;
    }

    void doSeek(uint32_t docid) override {
        ++seekCnt;
        if (docid <= 10) {
            setDocId(10);
        } else if (docid <= 20) {
            setDocId(20);
        } else {
            setAtEnd();
        }
    }

    void doUnpack(uint32_t docid) override {
        ++unpackCnt;
        if (match != 0) {
            _unpackedDocId = docid;
        }
    }
};
uint32_t DummyItr::seekCnt   = 0;
uint32_t DummyItr::unpackCnt = 0;
uint32_t DummyItr::dtorCnt   = 0;
uint32_t DummyItr::_unpackedDocId = 0;


TEST("filter wrapper forwards as expected") {
    EXPECT_EQUAL(DummyItr::seekCnt, 0u);
    EXPECT_EQUAL(DummyItr::unpackCnt, 0u);
    EXPECT_EQUAL(DummyItr::dtorCnt, 0u);
    { // without wrapper
        TermFieldMatchData match;
        DummyItr::_unpackedDocId = 0;
        SearchIterator::UP search(new DummyItr(&match));
        search->initFullRange();
        EXPECT_EQUAL(DummyItr::_unpackedDocId, 0u);
        EXPECT_TRUE(!search->seek(1u));
        EXPECT_EQUAL(search->getDocId(), 10u);
        EXPECT_TRUE(search->seek(10));
        search->unpack(10);
        EXPECT_EQUAL(DummyItr::_unpackedDocId, 10u);
        EXPECT_TRUE(!search->seek(15));
        EXPECT_EQUAL(search->getDocId(), 20u);
        EXPECT_TRUE(search->seek(20));
        search->unpack(20);
        EXPECT_EQUAL(DummyItr::_unpackedDocId, 20u);
        EXPECT_TRUE(!search->seek(25));
        EXPECT_TRUE(search->isAtEnd());
    }
    EXPECT_EQUAL(DummyItr::seekCnt, 3u);
    EXPECT_EQUAL(DummyItr::unpackCnt, 2u);
    EXPECT_EQUAL(DummyItr::dtorCnt, 1u);
    { // with wrapper
        TermFieldMatchData match;
        TermFieldMatchDataArray tfmda;
        tfmda.add(&match);
        DummyItr::_unpackedDocId = 0;
        auto search = std::make_unique<FilterWrapper>(1);
        auto to_wrap = std::make_unique<DummyItr>(search->tfmda()[0]);
        search->wrap(std::move(to_wrap));
        search->initFullRange();
        EXPECT_EQUAL(DummyItr::_unpackedDocId, 0u);
        EXPECT_TRUE(!search->seek(1u));
        EXPECT_EQUAL(search->getDocId(), 10u);
        EXPECT_TRUE(search->seek(10));
        search->unpack(10);
        EXPECT_EQUAL(DummyItr::_unpackedDocId, 0u);
        EXPECT_TRUE(!search->seek(15));
        EXPECT_EQUAL(search->getDocId(), 20u);
        EXPECT_TRUE(search->seek(20));
        search->unpack(20);
        EXPECT_EQUAL(DummyItr::_unpackedDocId, 0u);
        EXPECT_TRUE(!search->seek(25));
        EXPECT_TRUE(search->isAtEnd());
    }
    EXPECT_EQUAL(DummyItr::seekCnt, 6u);
    EXPECT_EQUAL(DummyItr::unpackCnt, 2u);
    EXPECT_EQUAL(DummyItr::dtorCnt, 2u);
}

class Verifier : public search::test::SearchIteratorVerifier {
public:
    ~Verifier();
    SearchIterator::UP create(bool strict) const override {
        auto search = std::make_unique<FilterWrapper>(1);
        search->wrap(createIterator(getExpectedDocIds(), strict));
        return search;
    }
};

Verifier::~Verifier() {}

TEST("Test that filter wrapper iterators adheres to SearchIterator requirements") {
    Verifier searchIteratorVerifier;
    searchIteratorVerifier.verify();
}

TEST_MAIN() { TEST_RUN_ALL(); }
