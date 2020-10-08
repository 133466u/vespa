// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#include "servicelayernode.h"
#include "bouncer.h"
#include "communicationmanager.h"
#include "changedbucketownershiphandler.h"
#include "mergethrottler.h"
#include "opslogger.h"
#include "statemanager.h"
#include "priorityconverter.h"
#include "service_layer_error_listener.h"
#include <vespa/storage/common/i_storage_chain_builder.h>
#include <vespa/storage/visiting/messagebusvisitormessagesession.h>
#include <vespa/storage/visiting/visitormanager.h>
#include <vespa/storage/bucketdb/bucketmanager.h>
#include <vespa/storage/bucketdb/storagebucketdbinitializer.h>
#include <vespa/storage/persistence/filestorage/filestormanager.h>
#include <vespa/storage/persistence/filestorage/modifiedbucketchecker.h>
#include <vespa/persistence/spi/exceptions.h>
#include <vespa/messagebus/rpcmessagebus.h>

#include <vespa/log/log.h>
LOG_SETUP(".node.servicelayer");


using StorServerConfigBuilder = vespa::config::content::core::StorServerConfigBuilder;

namespace storage {

ServiceLayerNode::ServiceLayerNode(const config::ConfigUri & configUri, ServiceLayerNodeContext& context,
                                   ApplicationGenerationFetcher& generationFetcher,
                                   spi::PersistenceProvider& persistenceProvider,
                                   const VisitorFactory::Map& externalVisitors)
    : StorageNode(configUri, context, generationFetcher, std::make_unique<HostInfo>()),
      _context(context),
      _persistenceProvider(persistenceProvider),
      _partitions(0),
      _externalVisitors(externalVisitors),
      _fileStorManager(nullptr),
      _init_has_been_called(false),
      _noUsablePartitionMode(false)
{
}

void ServiceLayerNode::init()
{
    assert( ! _init_has_been_called);
    _init_has_been_called = true;
    spi::Result initResult(_persistenceProvider.initialize());
    if (initResult.hasError()) {
        LOG(error, "Failed to initialize persistence provider: %s", initResult.toString().c_str());
        throw spi::HandledException("Failed provider init: " + initResult.toString(), VESPA_STRLOC);
    }

    spi::PartitionStateListResult result(_persistenceProvider.getPartitionStates());
    if (result.hasError()) {
        LOG(error, "Failed to get partition list from persistence provider: %s", result.toString().c_str());
        throw spi::HandledException("Failed to get partition list: " + result.toString(), VESPA_STRLOC);
    }
    _partitions = result.getList();
    if (_partitions.size() == 0) {
        LOG(error, "No partitions in persistence provider. See documentation "
                    "for your persistence provider as to how to set up partitions in it.");
        throw spi::HandledException("No partitions in provider", VESPA_STRLOC);
    }
    try{
        initialize();
    } catch (spi::HandledException& e) {
        requestShutdown("Failed to initialize: " + e.getMessage());
        throw;
    } catch (const vespalib::NetworkSetupFailureException & e) {
        LOG(warning, "Network failure: '%s'", e.what());
        throw;
    } catch (const vespalib::Exception & e) {
        LOG(error, "Caught exception %s during startup. Calling destruct functions in hopes of dying gracefully.",
            e.getMessage().c_str());
        requestShutdown("Failed to initialize: " + e.getMessage());
        throw;
    }
}

ServiceLayerNode::~ServiceLayerNode()
{
    assert(_init_has_been_called);
    shutdown();
}

void
ServiceLayerNode::subscribeToConfigs()
{
    StorageNode::subscribeToConfigs();
    _configFetcher.reset(new config::ConfigFetcher(_configUri.getContext()));

    std::lock_guard configLockGuard(_configLock);
        // Verify and set disk count
    if (_serverConfig->diskCount != 0
        && _serverConfig->diskCount != _partitions.size())
    {
        std::ostringstream ost;
        ost << "Storage is configured to have " << _serverConfig->diskCount
            << " disks but persistence provider states it has "
            << _partitions.size() << " disks.";
        throw vespalib::IllegalStateException(ost.str(), VESPA_STRLOC);
    }
    _context.getComponentRegister().setDiskCount(_partitions.size());
}

void
ServiceLayerNode::removeConfigSubscriptions()
{
    StorageNode::removeConfigSubscriptions();
    _configFetcher.reset();
}

void
ServiceLayerNode::initializeNodeSpecific()
{
    // Give node state to mount point initialization, such that we can
    // get disk count and state of unavailable disks set in reported
    // node state.
    NodeStateUpdater::Lock::SP lock(_component->getStateUpdater().grabStateChangeLock());
    lib::NodeState ns(*_component->getStateUpdater().getReportedNodeState());
    ns.setDiskCount(_partitions.size());

    uint32_t usablePartitions = 0;
    for (uint32_t i = 0; i < _partitions.size(); ++i) {
        if (_partitions[i].getState() == spi::PartitionState::UP) {
            ++usablePartitions;
        } else {
            lib::DiskState diskState(lib::State::DOWN, _partitions[i].getReason());
            ns.setDiskState(i, diskState);
        }
    }

    if (usablePartitions == 0) {
        _noUsablePartitionMode = true;
        ns.setState(lib::State::DOWN);
        ns.setDescription("All partitions are down");
    }
    ns.setCapacity(_serverConfig->nodeCapacity);
    ns.setReliability(_serverConfig->nodeReliability);
    for (uint16_t i=0; i<_serverConfig->diskCapacity.size(); ++i) {
        if (i >= ns.getDiskCount()) {
            LOG(warning, "Capacity configured for partition %zu but only %u partitions found.",
                _serverConfig->diskCapacity.size(), ns.getDiskCount());
            continue;
        }
        lib::DiskState ds(ns.getDiskState(i));
        ds.setCapacity(_serverConfig->diskCapacity[i]);
        ns.setDiskState(i, ds);
    }
    LOG(debug, "Adjusting reported node state to include partition count and states, capacity and reliability: %s",
        ns.toString().c_str());
    _component->getStateUpdater().setReportedNodeState(ns);
}

#define DIFFER(a) (!(oldC.a == newC.a))
#define ASSIGN(a) { oldC.a = newC.a; updated = true; }
#define DIFFERWARN(a, b) \
    if (DIFFER(a)) { LOG(warning, "Live config failure: %s.", b); }

void
ServiceLayerNode::handleLiveConfigUpdate(const InitialGuard & initGuard)
{
    if (_newServerConfig) {
        bool updated = false;
        vespa::config::content::core::StorServerConfigBuilder oldC(*_serverConfig);
        StorServerConfig& newC(*_newServerConfig);
        DIFFERWARN(diskCount, "Cannot alter partition count of node live");
        {
            updated = false;
            NodeStateUpdater::Lock::SP lock(_component->getStateUpdater().grabStateChangeLock());
            lib::NodeState ns(*_component->getStateUpdater().getReportedNodeState());
            if (DIFFER(nodeCapacity)) {
                LOG(info, "Live config update: Updating node capacity from %f to %f.",
                    oldC.nodeCapacity, newC.nodeCapacity);
                ASSIGN(nodeCapacity);
                ns.setCapacity(newC.nodeCapacity);
            }
            if (DIFFER(diskCapacity)) {
                for (uint32_t i=0; i<newC.diskCapacity.size() && i<ns.getDiskCount(); ++i) {
                    if (newC.diskCapacity[i] != oldC.diskCapacity[i]) {
                        lib::DiskState ds(ns.getDiskState(i));
                        ds.setCapacity(newC.diskCapacity[i]);
                        ns.setDiskState(i, ds);
                        LOG(info, "Live config update: Disk capacity of disk %u changed from %f to %f.",
                            i, oldC.diskCapacity[i], newC.diskCapacity[i]);
                    }
                }
                ASSIGN(diskCapacity);
            }
            if (DIFFER(nodeReliability)) {
                LOG(info, "Live config update: Node reliability changed from %u to %u.",
                    oldC.nodeReliability, newC.nodeReliability);
                ASSIGN(nodeReliability);
                ns.setReliability(newC.nodeReliability);
            }
            if (updated) {
                _serverConfig.reset(new vespa::config::content::core::StorServerConfig(oldC));
                _component->getStateUpdater().setReportedNodeState(ns);
            }
        }
    }
    StorageNode::handleLiveConfigUpdate(initGuard);
}

VisitorMessageSession::UP
ServiceLayerNode::createSession(Visitor& visitor, VisitorThread& thread)
{
    auto mbusSession = std::make_unique<MessageBusVisitorMessageSession>(visitor, thread);
    mbus::SourceSessionParams srcParams;
    srcParams.setThrottlePolicy(mbus::IThrottlePolicy::SP());
    srcParams.setReplyHandler(*mbusSession);
    mbusSession->setSourceSession(_communicationManager->getMessageBus().getMessageBus().createSourceSession(srcParams));
    return VisitorMessageSession::UP(std::move(mbusSession));
}

documentapi::Priority::Value
ServiceLayerNode::toDocumentPriority(uint8_t storagePriority) const
{
    return _communicationManager->getPriorityConverter().toDocumentPriority(storagePriority);
}

void
ServiceLayerNode::createChain(IStorageChainBuilder &builder)
{
    ServiceLayerComponentRegister& compReg(_context.getComponentRegister());

    auto communication_manager = std::make_unique<CommunicationManager>(compReg, _configUri);
    _communicationManager = communication_manager.get();
    builder.add(std::move(communication_manager));
    builder.add(std::make_unique<Bouncer>(compReg, _configUri));
    if (_noUsablePartitionMode) {
        /*
         * No usable partitions. Use minimal chain. Still needs to be
         * able to report state back to cluster controller.
         */
        builder.add(releaseStateManager());
        return;
    }
    builder.add(std::make_unique<OpsLogger>(compReg, _configUri));
    auto merge_throttler_up = std::make_unique<MergeThrottler>(_configUri, compReg);
    auto merge_throttler = merge_throttler_up.get();
    builder.add(std::move(merge_throttler_up));
    builder.add(std::make_unique<ChangedBucketOwnershipHandler>(_configUri, compReg));
    builder.add(std::make_unique<StorageBucketDBInitializer>(
            _configUri, _partitions, getDoneInitializeHandler(), compReg));
    builder.add(std::make_unique<BucketManager>(_configUri, _context.getComponentRegister()));
    builder.add(std::make_unique<VisitorManager>(_configUri, _context.getComponentRegister(), static_cast<VisitorMessageSessionFactory &>(*this), _externalVisitors));
    builder.add(std::make_unique<ModifiedBucketChecker>(
            _context.getComponentRegister(), _persistenceProvider, _configUri));
    auto filstor_manager = std::make_unique<FileStorManager>(_configUri, _partitions, _persistenceProvider, _context.getComponentRegister());
    _fileStorManager = filstor_manager.get();
    builder.add(std::move(filstor_manager));
    builder.add(releaseStateManager());

    // Lifetimes of all referenced components shall outlive the last call going
    // through the SPI, as queues are flushed and worker threads joined when
    // the storage link chain is closed prior to destruction.
    auto error_listener = std::make_shared<ServiceLayerErrorListener>(*_component, *merge_throttler);
    _fileStorManager->error_wrapper().register_error_listener(std::move(error_listener));
}

ResumeGuard
ServiceLayerNode::pause()
{
    return _fileStorManager->getFileStorHandler().pause();
}

} // storage
