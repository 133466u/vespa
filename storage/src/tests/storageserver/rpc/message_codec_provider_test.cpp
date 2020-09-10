// Copyright Verizon Media. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
#include <vespa/storage/storageserver/rpc/message_codec_provider.h>
#include <vespa/storageapi/mbusprot/protocolserialization7.h>
#include <vespa/document/base/testdocman.h>
#include <vespa/documentapi/loadtypes/loadtypeset.h>
#include <vespa/vespalib/gtest/gtest.h>

using namespace ::testing;

namespace storage::rpc {

struct MessageCodecProviderTest : Test {
    std::shared_ptr<const document::DocumentTypeRepo> _repo1;
    std::shared_ptr<const document::DocumentTypeRepo> _repo2;
    std::shared_ptr<const documentapi::LoadTypeSet> _load_types1;
    std::shared_ptr<const documentapi::LoadTypeSet> _load_types2;
    MessageCodecProvider _provider;

    // We don't care about repo/set contents, just their pointer identities
    MessageCodecProviderTest()
        : _repo1(document::TestDocRepo().getTypeRepoSp()),
          _repo2(document::TestDocRepo().getTypeRepoSp()),
          _load_types1(std::make_shared<documentapi::LoadTypeSet>()),
          _load_types2(std::make_shared<documentapi::LoadTypeSet>()),
          _provider(_repo1, _load_types1)
    {}
    ~MessageCodecProviderTest() override;
};

MessageCodecProviderTest::~MessageCodecProviderTest() = default;

TEST_F(MessageCodecProviderTest, initially_provides_constructed_repos) {
    auto wrapped = _provider.wrapped_codec();
    EXPECT_EQ(&wrapped->codec().type_repo(), _repo1.get());
    EXPECT_EQ(&wrapped->codec().load_type_set(), _load_types1.get());
}

TEST_F(MessageCodecProviderTest, updated_repos_reflected_in_new_wrapped_codec) {
    _provider.update_atomically(_repo2, _load_types2);

    auto wrapped = _provider.wrapped_codec();
    EXPECT_EQ(&wrapped->codec().type_repo(), _repo2.get());
    EXPECT_EQ(&wrapped->codec().load_type_set(), _load_types2.get());
}

}
