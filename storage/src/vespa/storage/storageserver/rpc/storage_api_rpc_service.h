// Copyright Verizon Media. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
#pragma once

#include "rpc_target.h"
#include <vespa/fnet/frt/invokable.h>
#include <vespa/fnet/frt/invoker.h>
#include <vespa/storageapi/messageapi/returncode.h>
#include <vespa/vespalib/stllike/string.h>
#include <vespa/vespalib/util/compressionconfig.h>
#include <atomic>
#include <memory>

class FRT_RPCRequest;
class FRT_Target;

namespace document { class DocumentTypeRepo; }
namespace documentapi { class LoadTypeSet; }

namespace storage {

class MessageDispatcher;

namespace api {
class StorageCommand;
class StorageMessage;
class StorageMessageAddress;
class StorageReply;
}

namespace rpc {

class CachingRpcTargetResolver;
class MessageCodecProvider;
class SharedRpcResources;

class StorageApiRpcService : public FRT_Invokable, public FRT_IRequestWait {
public:
    struct Params {
        vespalib::compression::CompressionConfig compression_config;

        Params();
        ~Params();
    };
private:
    MessageDispatcher&    _message_dispatcher;
    SharedRpcResources&   _rpc_resources;
    MessageCodecProvider& _message_codec_provider;
    const Params          _params;
    std::unique_ptr<CachingRpcTargetResolver> _target_resolver;
public:
    StorageApiRpcService(MessageDispatcher& message_dispatcher,
                         SharedRpcResources& rpc_resources,
                         MessageCodecProvider& message_codec_provider,
                         const Params& params);
    ~StorageApiRpcService() override;

    void RPC_rpc_v1_send(FRT_RPCRequest* req);
    void encode_rpc_v1_response(FRT_RPCRequest& request, const api::StorageReply& reply);
    void send_rpc_v1_request(std::shared_ptr<api::StorageCommand> cmd);
private:
    // TODO dedupe
    void detach_and_forward_to_enqueuer(std::shared_ptr<api::StorageMessage> cmd, FRT_RPCRequest* req);

    struct RpcRequestContext {
        std::shared_ptr<api::StorageCommand> _originator_cmd;

        explicit RpcRequestContext(std::shared_ptr<api::StorageCommand> cmd)
            : _originator_cmd(std::move(cmd))
        {}
    };

    void register_server_methods(SharedRpcResources&);
    template <typename PayloadCodecCallback>
    void uncompress_rpc_payload(const FRT_Values& params, PayloadCodecCallback payload_callback);
    template <typename MessageType>
    void encode_and_compress_rpc_payload(const MessageType& msg, FRT_Values& params);
    void RequestDone(FRT_RPCRequest* request) override;

    api::ReturnCode map_frt_error_to_storage_api_error(FRT_RPCRequest& req, const RpcRequestContext& req_ctx);
    api::ReturnCode make_no_address_for_service_error(const api::StorageMessageAddress& addr) const;
};

} // rpc
} // storage
