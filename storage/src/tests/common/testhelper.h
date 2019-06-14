// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
#pragma once
#include <vespa/vdstestlib/cppunit/dirconfig.h>
#include <vespa/vdstestlib/cppunit/macros.h>


#include <fstream>
#include <vespa/messagebus/testlib/slobrok.h>
#include <sstream>

#define ASSERT_REPLY_COUNT(count, dummylink) \
    { \
        std::ostringstream msgost; \
        if ((dummylink).getNumReplies() != count) { \
            for (uint32_t ijx=0; ijx<(dummylink).getNumReplies(); ++ijx) { \
                msgost << (dummylink).getReply(ijx)->toString(true) << "\n"; \
            } \
        } \
        CPPUNIT_ASSERT_EQUAL_MSG(msgost.str(), size_t(count), \
                                 (dummylink).getNumReplies()); \
    }

namespace storage {

void addFileConfig(vdstestlib::DirConfig& dc,
                   const std::string& configDefName,
                   const std::string& fileName);


void addStorageDistributionConfig(vdstestlib::DirConfig& dc);

vdstestlib::DirConfig getStandardConfig(bool storagenode, const std::string & rootFolder = "todo-make-unique");

std::string getRootFolder(vdstestlib::DirConfig & dc);

void addSlobrokConfig(vdstestlib::DirConfig& dc,
                      const mbus::Slobrok& slobrok);

// Class used to print start and end of test. Enable debug when you want to see
// which test creates what output or where we get stuck
struct TestName {
    std::string name;
    TestName(const std::string& n);
    ~TestName();
};

} // storage

