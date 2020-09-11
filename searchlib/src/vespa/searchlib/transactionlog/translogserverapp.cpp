// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#include "translogserverapp.h"
#include <vespa/config/subscription/configuri.h>
#include <vespa/vespalib/util/time.h>

#include <vespa/log/log.h>
LOG_SETUP(".translogserverapp");

using search::common::FileHeaderContext;

namespace search::transactionlog {

TransLogServerApp::TransLogServerApp(const config::ConfigUri & tlsConfigUri,
                                     const FileHeaderContext & fileHeaderContext)
    : _lock(),
      _tls(),
      _tlsConfig(),
      _tlsConfigFetcher(tlsConfigUri.getContext()),
      _fileHeaderContext(fileHeaderContext)
{
    _tlsConfigFetcher.subscribe<searchlib::TranslogserverConfig>(tlsConfigUri.getConfigId(), this);
    _tlsConfigFetcher.start();
}

namespace {

Encoding::Crc
getCrc(searchlib::TranslogserverConfig::Crcmethod crcType)
{
    switch (crcType) {
        case searchlib::TranslogserverConfig::Crcmethod::ccitt_crc32:
            return Encoding::Crc::ccitt_crc32;
        case searchlib::TranslogserverConfig::Crcmethod::xxh64:
            return Encoding::Crc::xxh64;
    }
    assert(false);
}

Encoding::Compression
getCompression(searchlib::TranslogserverConfig::Compression::Type type)
{
    switch (type) {
        case searchlib::TranslogserverConfig::Compression::Type::NONE:
            return Encoding::Compression::none;
        case searchlib::TranslogserverConfig::Compression::Type::NONE_MULTI:
            return Encoding::Compression::none_multi;
        case searchlib::TranslogserverConfig::Compression::Type::LZ4:
            return Encoding::Compression::lz4;
        case searchlib::TranslogserverConfig::Compression::Type::ZSTD:
            return Encoding::Compression::zstd;
    }
    assert(false);
}

Encoding
getEncoding(const searchlib::TranslogserverConfig & cfg)
{
    return Encoding(getCrc(cfg.crcmethod), getCompression(cfg.compression.type));
}

DomainConfig
getDomainConfig(const searchlib::TranslogserverConfig & cfg) {
    DomainConfig dcfg;
    dcfg.setEncoding(getEncoding(cfg))
        .setCompressionLevel(cfg.compression.level)
        .setPartSizeLimit(cfg.filesizemax)
        .setChunkSizeLimit(cfg.chunk.sizelimit)
        .setChunkAgeLimit(vespalib::from_s(cfg.chunk.agelimit))
        .setFSyncOnCommit(cfg.usefsync);
    return dcfg;
}

void
logReconfig(const searchlib::TranslogserverConfig & cfg, const DomainConfig & dcfg) {
    LOG(config, "configure Transaction Log Server %s at port %d\n"
                "DomainConfig {encoding={%d, %d}, compression_level=%d, part_limit=%ld, chunk_limit=%ld age=%1.4f}",
        cfg.servername.c_str(), cfg.listenport,
        dcfg.getEncoding().getCrc(), dcfg.getEncoding().getCompression(), dcfg.getCompressionlevel(),
        dcfg.getPartSizeLimit(), dcfg.getChunkSizeLimit(), vespalib::to_s(dcfg.getChunkAgeLimit())
    );
}

}

void
TransLogServerApp::start()
{
    std::lock_guard<std::mutex> guard(_lock);
    auto c = _tlsConfig.get();
    DomainConfig domainConfig = getDomainConfig(*c);
    logReconfig(*c, domainConfig);
   _tls = std::make_shared<TransLogServer>(c->servername, c->listenport, c->basedir, _fileHeaderContext,
                                            domainConfig, c->maxthreads);
}

TransLogServerApp::~TransLogServerApp()
{
    _tlsConfigFetcher.close();
}

void
TransLogServerApp::configure(std::unique_ptr<searchlib::TranslogserverConfig> cfg)
{

    std::lock_guard<std::mutex> guard(_lock);
    DomainConfig dcfg = getDomainConfig(*cfg);
    logReconfig(*cfg, dcfg);
    _tlsConfig.set(cfg.release());
    _tlsConfig.latch();
    if (_tls) {
        _tls->setDomainConfig(dcfg);
    }
}

TransLogServer::SP
TransLogServerApp::getTransLogServer() const {
    std::lock_guard<std::mutex> guard(_lock);
    return _tls;
}

}
