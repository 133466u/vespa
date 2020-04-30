// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
#pragma once

#include <vespa/storage/common/bucketmessages.h>
#include <vespa/storage/persistence/persistenceutil.h>

namespace storage {

class DiskMoveOperationHandler : public Types {

public:
    DiskMoveOperationHandler(PersistenceUtil&,
                             spi::PersistenceProvider& provider);

    MessageTracker::UP handleBucketDiskMove(BucketDiskMoveCommand&, MessageTracker::UP tracker);

private:
    PersistenceUtil& _env;
    spi::PersistenceProvider& _provider;
};

} // storage

