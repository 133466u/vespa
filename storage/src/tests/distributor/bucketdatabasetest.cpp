// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
#include "bucketdatabasetest.h"
#include <iomanip>
#include <algorithm>

namespace storage::distributor {

using document::BucketId;

void BucketDatabaseTest::SetUp() {
    db().clear();
}

namespace {
    BucketCopy BC(uint32_t nodeIdx) {
        return BucketCopy(0, nodeIdx, api::BucketInfo());
    }

    BucketInfo BI(uint32_t nodeIdx) {
        BucketInfo bi;
        bi.addNode(BC(nodeIdx), toVector<uint16_t>(0));
        return bi;
    }
}

TEST_P(BucketDatabaseTest, testClear) {
    db().update(BucketDatabase::Entry(document::BucketId(16, 16), BI(1)));
    db().update(BucketDatabase::Entry(document::BucketId(16, 11), BI(2)));
    db().clear();
    EXPECT_EQ(uint64_t(0), db().size());
}

TEST_P(BucketDatabaseTest, testUpdateGetAndRemove) {
    // Do some insertions
    EXPECT_EQ(0, db().size());
    db().update(BucketDatabase::Entry(document::BucketId(16, 16), BI(1)));
    db().update(BucketDatabase::Entry(document::BucketId(16, 11), BI(2)));
    db().update(BucketDatabase::Entry(document::BucketId(16, 42), BI(3)));
    EXPECT_EQ(3, db().size());

    db().update(BucketDatabase::Entry(document::BucketId(16, 11), BI(4)));
    EXPECT_EQ(3, db().size());

    // Access some elements
    EXPECT_EQ(BI(4), db().get(document::BucketId(16, 11)).getBucketInfo());
    EXPECT_EQ(BI(1), db().get(document::BucketId(16, 16)).getBucketInfo());
    EXPECT_EQ(BI(3), db().get(document::BucketId(16, 42)).getBucketInfo());

    // Do removes
    db().remove(document::BucketId(16, 12));

    EXPECT_EQ(3, db().size());

    db().remove(document::BucketId(16, 11));

    EXPECT_EQ(2, db().size());

    db().remove(document::BucketId(16, 16));
    db().remove(document::BucketId(16, 42));

    EXPECT_EQ(0, db().size());
}

namespace {

struct ModifyProcessor : public BucketDatabase::MutableEntryProcessor
{
    bool process(BucketDatabase::Entry& e) override {
        if (e.getBucketId() == document::BucketId(16, 0x0b)) {
            e.getBucketInfo() = BI(7);
        } else if (e.getBucketId() == document::BucketId(16, 0x2a)) {
            e->clear();
            e->addNode(BC(4), toVector<uint16_t>(0));
            e->addNode(BC(5), toVector<uint16_t>(0));
        }

        return true;
    }
};

struct ListAllProcessor : public BucketDatabase::EntryProcessor {
    std::ostringstream ost;

    bool process(const BucketDatabase::Entry& e) override {
        ost << e << "\n";
        return true;
    }
};

struct DummyProcessor : public BucketDatabase::EntryProcessor {
    std::ostringstream ost;

    bool process(const BucketDatabase::Entry&) override {
        return true;
    }
};


struct StoppingProcessor : public BucketDatabase::EntryProcessor {
    std::ostringstream ost;

    bool process(const BucketDatabase::Entry& e) override {
        ost << e << "\n";

        if (e.getBucketId() == document::BucketId(16, 0x2a)) {
            return false;
        }

        return true;
    }
};

}

TEST_P(BucketDatabaseTest, testIterating) {
    // Do some insertions
    db().update(BucketDatabase::Entry(document::BucketId(16, 0x10), BI(1)));
    db().update(BucketDatabase::Entry(document::BucketId(16, 0x0b), BI(2)));
    db().update(BucketDatabase::Entry(document::BucketId(16, 0x2a), BI(3)));

    {
        ListAllProcessor proc;
        db().forEach(proc, document::BucketId());

        EXPECT_EQ(
                std::string(
                        "BucketId(0x4000000000000010) : "
                        "node(idx=1,crc=0x0,docs=0/0,bytes=1/1,trusted=false,active=false,ready=false)\n"
                        "BucketId(0x400000000000002a) : "
                        "node(idx=3,crc=0x0,docs=0/0,bytes=1/1,trusted=false,active=false,ready=false)\n"
                        "BucketId(0x400000000000000b) : "
                        "node(idx=2,crc=0x0,docs=0/0,bytes=1/1,trusted=false,active=false,ready=false)\n"),
                proc.ost.str());
    }

    {
        ListAllProcessor proc;
        db().forEach(proc, document::BucketId(16, 0x2a));

        EXPECT_EQ(
                std::string(
                        "BucketId(0x400000000000000b) : "
                        "node(idx=2,crc=0x0,docs=0/0,bytes=1/1,trusted=false,active=false,ready=false)\n"),
                proc.ost.str());
    }

    {
        StoppingProcessor proc;
        db().forEach(proc, document::BucketId());

        EXPECT_EQ(
                std::string(
                        "BucketId(0x4000000000000010) : "
                        "node(idx=1,crc=0x0,docs=0/0,bytes=1/1,trusted=false,active=false,ready=false)\n"
                        "BucketId(0x400000000000002a) : "
                        "node(idx=3,crc=0x0,docs=0/0,bytes=1/1,trusted=false,active=false,ready=false)\n"),
                proc.ost.str());
    }

    {
        ModifyProcessor alterProc;
        db().forEach(alterProc, document::BucketId());
            // Verify content after altering
        ListAllProcessor proc;
        db().forEach(proc);

        EXPECT_EQ(
                std::string(
                        "BucketId(0x4000000000000010) : "
                        "node(idx=1,crc=0x0,docs=0/0,bytes=1/1,trusted=false,active=false,ready=false)\n"
                        "BucketId(0x400000000000002a) : "
                        "node(idx=4,crc=0x0,docs=0/0,bytes=1/1,trusted=false,active=false,ready=false), "
                        "node(idx=5,crc=0x0,docs=0/0,bytes=1/1,trusted=false,active=false,ready=false)\n"
                        "BucketId(0x400000000000000b) : "
                        "node(idx=7,crc=0x0,docs=0/0,bytes=1/1,trusted=false,active=false,ready=false)\n"),
                proc.ost.str());
    }
}

std::string
BucketDatabaseTest::doFindParents(const std::vector<document::BucketId>& ids,
                                  const document::BucketId& searchId)
{
    db().clear();

    for (uint32_t i = 0; i < ids.size(); ++i) {
        db().update(BucketDatabase::Entry(ids[i], BI(i)));
    }

    std::vector<BucketDatabase::Entry> entries;
    db().getParents(searchId, entries);

    std::ostringstream ost;
    for (uint32_t i = 0; i < ids.size(); ++i) {
        if (std::find(entries.begin(), entries.end(),
                      BucketDatabase::Entry(ids[i], BI(i))) != entries.end()) {
            if (!ost.str().empty()) {
                ost << ",";
            }
            ost << i;
        }
    }

    return ost.str();
}

TEST_P(BucketDatabaseTest, testFindParents) {
    // test what parents in the DB (specified in vector) are parents of the
    // specified bucket. Result is a list of indexes into the vector.

    // The way the legacy API works is that a bucket is considered as being in
    // the set of its parents... This is rather weird, but at least explicitly
    // test that it is so for now to avoid breaking the world.
    EXPECT_EQ(
            std::string("0"),
            doFindParents(toVector(document::BucketId(17, 0xcafe)),
                          document::BucketId(17, 0xcafe)));

    EXPECT_EQ(
            std::string("1,2"),
            doFindParents(toVector(document::BucketId(1, 0x0),
                                   document::BucketId(1, 0x1),
                                   document::BucketId(2, 0x1)),
                          document::BucketId(16, 0x1)));

    EXPECT_EQ(
            std::string("2"),
            doFindParents(toVector(document::BucketId(17, 0x0ffff),
                                   document::BucketId(18, 0x1ffff),
                                   document::BucketId(18, 0x3ffff)),
                          document::BucketId(22, 0xfffff)));

    EXPECT_EQ(
            std::string("0,2,3"),
            doFindParents(toVector(document::BucketId(16, 0x0ffff),
                                   document::BucketId(17, 0x0ffff),
                                   document::BucketId(17, 0x1ffff),
                                   document::BucketId(19, 0xfffff)),
                          document::BucketId(22, 0xfffff)));

    EXPECT_EQ(
            std::string("0,1,2,3"),
            doFindParents(toVector(document::BucketId(16, 0x0ffff),
                                   document::BucketId(17, 0x0ffff),
                                   document::BucketId(18, 0x0ffff),
                                   document::BucketId(19, 0x0ffff)),
                          document::BucketId(20, 0x0ffff)));

    EXPECT_EQ(
            std::string("0,2,3"),
            doFindParents(toVector(document::BucketId(16, 0x0ffff),
                                   document::BucketId(17, 0x0ffff),
                                   document::BucketId(17, 0x1ffff),
                                   document::BucketId(18, 0x1ffff)),
                          document::BucketId(22, 0x1ffff)));

    EXPECT_EQ(
            std::string("0"),
            doFindParents(toVector(document::BucketId(16, 0x0ffff),
                                   document::BucketId(17, 0x0ffff)),
                          document::BucketId(22, 0x1ffff)));

    EXPECT_EQ( // ticket 3121525
            std::string("0"),
            doFindParents(toVector(document::BucketId(16, 0x0ffff),
                                   document::BucketId(17, 0x0ffff),
                                   document::BucketId(19, 0x1ffff)),
                          document::BucketId(18, 0x1ffff)));

    EXPECT_EQ( // ticket 3121525
            std::string("0"),
            doFindParents(toVector(document::BucketId(16, 0x0ffff),
                                   document::BucketId(17, 0x0ffff),
                                   document::BucketId(19, 0x5ffff)),
                          document::BucketId(18, 0x1ffff)));
}

std::string
BucketDatabaseTest::doFindAll(const std::vector<document::BucketId>& ids,
                              const document::BucketId& searchId)
{
    db().clear();

    for (uint32_t i = 0; i < ids.size(); ++i) {
        db().update(BucketDatabase::Entry(ids[i], BI(i)));
    }

    std::vector<BucketDatabase::Entry> entries;
    db().getAll(searchId, entries);

    std::ostringstream ost;
    for (uint32_t i = 0; i < ids.size(); ++i) {
        auto wanted = BucketDatabase::Entry(ids[i], BI(i));
        for (const auto& e : entries) {
            if (!(e == wanted)) {
                continue;
            }
            if (!ost.str().empty()) {
                ost << ",";
            }
            ost << i;
        }
    }

    return ost.str();
}

TEST_P(BucketDatabaseTest, testFindAll) {
    std::vector<document::BucketId> buckets;
    EXPECT_EQ(
            std::string(""),
            doFindAll(buckets, document::BucketId(18, 0x1ffff)));

    buckets.push_back(document::BucketId(16, 0x0aaaa)); // contains bucket 2-7
    buckets.push_back(document::BucketId(17, 0x0aaaa)); // contains bucket 3-4
    buckets.push_back(document::BucketId(20, 0xcaaaa));
    buckets.push_back(document::BucketId(20, 0xeaaaa));
    buckets.push_back(document::BucketId(17, 0x1aaaa)); // contains bucket 6-7
    buckets.push_back(document::BucketId(20, 0xdaaaa));
    buckets.push_back(document::BucketId(20, 0xfaaaa));
    buckets.push_back(document::BucketId(20, 0xceaaa));
    buckets.push_back(document::BucketId(17, 0x1ffff));

    EXPECT_EQ(
            std::string("0"),
            doFindAll(toVector(document::BucketId(16, 1234)),
                      document::BucketId(16, 1234)));

    EXPECT_EQ(
            std::string("0,4,5,6"),
            doFindAll(buckets, document::BucketId(17, 0x1aaaa)));

    EXPECT_EQ(
            std::string("8"),
            doFindAll(buckets, document::BucketId(16, 0xffff)));

    EXPECT_EQ(
            std::string("0,1"),
            doFindAll(toVector(document::BucketId(17, 0x00001),
                               document::BucketId(17, 0x10001)),
                      document::BucketId(16, 0x00001)));

    document::BucketId id(33, 0x1053c7089); // Bit 32 is set, but unused.
    id.setUsedBits(32);
    EXPECT_EQ(
            std::string("1,2"),
            doFindAll(toVector(document::BucketId(24, 0x000dc7089),
                               document::BucketId(33, 0x0053c7089),
                               document::BucketId(33, 0x1053c7089),
                               document::BucketId(24, 0x000bc7089)),
                      id));

    EXPECT_EQ( // Inconsistent split
            std::string("0,1,2"),
            doFindAll(toVector(
                              document::BucketId(16, 0x00001), // contains 2-3
                              document::BucketId(17, 0x00001),
                              document::BucketId(17, 0x10001)),
                      document::BucketId(16, 0x00001)));

    EXPECT_EQ( // Inconsistent split
            std::string("1,2"),
            doFindAll(toVector(
                              document::BucketId(17, 0x10000),
                              document::BucketId(27, 0x007228034), // contains 3
                              document::BucketId(29, 0x007228034),
                              document::BucketId(17, 0x1ffff)),
                      document::BucketId(32, 0x027228034)));

    EXPECT_EQ( // Inconsistent split
            std::string("0"),
            doFindAll(toVector(
                              document::BucketId(16, 0x0ffff),
                              document::BucketId(17, 0x0ffff)),
                      document::BucketId(22, 0x1ffff)));

    EXPECT_EQ( // Inconsistent split
            std::string("0,2"),
            doFindAll(toVector(
                              document::BucketId(16, 0x0ffff),
                              document::BucketId(17, 0x0ffff),
                              document::BucketId(19, 0x1ffff)),
                      document::BucketId(18, 0x1ffff)));

    EXPECT_EQ( // Inconsistent split, ticket 3121525
            std::string("0,2"),
            doFindAll(toVector(
                              document::BucketId(16, 0x0ffff),
                              document::BucketId(17, 0x0ffff),
                              document::BucketId(19, 0x5ffff)),
                      document::BucketId(18, 0x1ffff)));
}

document::BucketId
BucketDatabaseTest::doCreate(const std::vector<document::BucketId>& ids,
                             uint32_t minBits,
                             const document::BucketId& wantedId)
{
    db().clear();

    for (uint32_t i = 0; i < ids.size(); ++i) {
        db().update(BucketDatabase::Entry(ids[i], BI(i)));
    }

    BucketDatabase::Entry entry = db().createAppropriateBucket(minBits, wantedId);
    return entry.getBucketId();
}

// TODO rewrite in terms of bucket getter, not creator
TEST_P(BucketDatabaseTest, testCreateAppropriateBucket) {
        // Use min split bits when no relevant bucket exist.
    EXPECT_EQ(
            document::BucketId(36,0x0000004d2),
            doCreate(toVector(document::BucketId(58, 0x43d6c878000004d2ull)), 36,
                     document::BucketId(58, 0x423bf1e0000004d2ull)));
    // New bucket has bits in common with existing bucket.
    // Create bucket with min amount of bits while not being overlapping
    EXPECT_EQ(
            document::BucketId(34,0x0000004d2),
            doCreate(toVector(document::BucketId(58, 0xeaf77782000004d2)),
                     16,
                     document::BucketId(58, 0x00000000000004d2)));
    // Create sibling of existing bucket with most LSB bits in common.
    EXPECT_EQ(
            document::BucketId(40, 0x0000004d2),
            doCreate(toVector(document::BucketId(58, 0xeaf77780000004d2),
                              document::BucketId(58, 0xeaf77782000004d2)),
                     16,
                     document::BucketId(58, 0x00000000000004d2)));
    // Create sibling of existing bucket with most LSB bits in common.
    EXPECT_EQ(
            document::BucketId(25, 0x0010004d2),
            doCreate(toVector(document::BucketId(16, 0x00000000000004d1),
                              document::BucketId(40, 0x00000000000004d2)),
                     16,
                     document::BucketId(58, 0x00000000010004d2)));

    EXPECT_EQ(
            document::BucketId(36, 0x10000004000004d2),
            doCreate(toVector(document::BucketId(0x8c000000000004d2),
                              document::BucketId(0xeb54b3ac000004d2),
                              document::BucketId(0x88000002000004d2),
                              document::BucketId(0x84000001000004d2)),
                     16,
                     document::BucketId(58, 0x1944a44000004d2)));
    EXPECT_EQ(
            document::BucketId(25, 0x0010004d2),
            doCreate(toVector(document::BucketId(58, 0xeaf77780000004d2),
                              document::BucketId(40, 0x00000000000004d1)),
                     16,
                     document::BucketId(58,0x00000000010004d2)));
    // Test empty bucket database case. (Use min split bits)
    std::vector<document::BucketId> buckets;
    EXPECT_EQ(
            document::BucketId(16, 0x0000004d2ull),
            doCreate(buckets, 16,
                     document::BucketId(58, 0x00000000010004d2)));
}

TEST_P(BucketDatabaseTest, testGetNext) {
    db().update(BucketDatabase::Entry(document::BucketId(16, 16), BI(1)));
    db().update(BucketDatabase::Entry(document::BucketId(16, 11), BI(2)));
    db().update(BucketDatabase::Entry(document::BucketId(16, 42), BI(3)));

    EXPECT_EQ(document::BucketId(16, 16),
              db().getNext(document::BucketId()).getBucketId());

    EXPECT_EQ(document::BucketId(16, 42),
              db().getNext(document::BucketId(16, 16)).getBucketId());

    EXPECT_EQ(document::BucketId(16, 11),
              db().getNext(document::BucketId(16, 42)).getBucketId());
}

void
BucketDatabaseTest::doTestUpperBound(const UBoundFunc& f)
{
    // Tree is rooted at the LSB bit, so the following buckets are in iteration
    // order based on the reverse of their "normal" bitstring:
    // 0010:3
    db().update(BucketDatabase::Entry(document::BucketId(3, 4), BI(2)));
    // 1000:3
    db().update(BucketDatabase::Entry(document::BucketId(3, 1), BI(2)));
    // 1001:4
    db().update(BucketDatabase::Entry(document::BucketId(4, 9), BI(1)));
    // 10010:5
    db().update(BucketDatabase::Entry(document::BucketId(5, 9), BI(1)));
    // 1100:3
    db().update(BucketDatabase::Entry(document::BucketId(3, 3), BI(3)));

    // 0000:0 (default constructed) has ubound of 0010:3
    EXPECT_EQ(BucketId(3, 4), f(db(), BucketId()));
    // 0011:4 has ubound of 1000:3
    EXPECT_EQ(document::BucketId(3, 1), f(db(), BucketId(4, 12)));
    // 1000:1 has ubound of 1000:3
    EXPECT_EQ(BucketId(3, 4), f(db(), BucketId(1, 0)));
    EXPECT_EQ(BucketId(3, 1), f(db(), BucketId(3, 4)));
    EXPECT_EQ(BucketId(4, 9), f(db(), BucketId(3, 1)));
    EXPECT_EQ(BucketId(5, 9), f(db(), BucketId(4, 9)));
    EXPECT_EQ(BucketId(3, 3), f(db(), BucketId(5, 9)));
    // 100101:6 does not exist, should also return 1100:3
    EXPECT_EQ(BucketId(3, 3), f(db(), BucketId(6, 41)));

    // Test extremes.
    db().clear();
    db().update(BucketDatabase::Entry(document::BucketId(8, 0), BI(2)));
    db().update(BucketDatabase::Entry(document::BucketId(8, 0xff), BI(2)));

    EXPECT_EQ(BucketId(8, 0), f(db(), BucketId()));
    EXPECT_EQ(BucketId(8, 0xff), f(db(), BucketId(8, 0)));
}

TEST_P(BucketDatabaseTest, testUpperBoundReturnsNextInOrderGreaterBucket) {
    doTestUpperBound([](const BucketDatabase& bucketDb,
                        const document::BucketId& id)
    {
        return bucketDb.upperBound(id).getBucketId();
    });
}

TEST_P(BucketDatabaseTest, testGetNextReturnsUpperBoundBucket) {
    // getNext() would generally be implemented in terms of upperBound(), but
    // make sure it conforms to the same contract in case this changes.
    doTestUpperBound([](const BucketDatabase& bucketDb,
                        const document::BucketId& id)
    {
        return bucketDb.getNext(id).getBucketId();
    });
}

TEST_P(BucketDatabaseTest, testChildCount) {
    // Empty tree; inserts cannot create inconsistencies.
    EXPECT_EQ(0u, db().childCount(BucketId(3, 1)));

    // Same bucket; cannot be inconsistent with itself.
    db().update(BucketDatabase::Entry(document::BucketId(3, 1), BI(1)));
    EXPECT_EQ(0u, db().childCount(BucketId(3, 1)));

    // (2, 1) has one subtree.
    EXPECT_EQ(1u, db().childCount(BucketId(2, 1)));

    // Bucket exists in another subtree from (1, 1); inconsistency would
    // result if we tried inserting it.
    db().update(BucketDatabase::Entry(document::BucketId(3, 3), BI(2)));
    EXPECT_EQ(2u, db().childCount(BucketId(1, 1)));

    // Inner node with 1 subtree.
    EXPECT_EQ(1u, db().childCount(BucketId(2, 3)));

    // Leaves have no subtrees.
    EXPECT_EQ(0u, db().childCount(BucketId(3, 1)));
    EXPECT_EQ(0u, db().childCount(BucketId(3, 5)));
}

}
