// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#include "activecopy.h"

#include <vespa/storage/storageutil/utils.h>
#include <vespa/vdslib/distribution/distribution.h>
#include <vespa/vespalib/stllike/asciistream.h>
#include <algorithm>
#include <cassert>

namespace std {
    template<typename T>
    std::ostream& operator<<(std::ostream& out, const std::vector<T>& v) {
        out << "[";
        for (uint32_t i=0; i<v.size(); ++i) {
            out << "\n  " << v[i];
        }
        if (!v.empty()) out << "\n";
        return out << "]";
    }
}

namespace storage::distributor {

ActiveCopy::ActiveCopy(uint16_t node, const BucketDatabase::Entry& e, const std::vector<uint16_t>& idealState) :
    _nodeIndex(node),
    _ideal(0xffff)
{
    const BucketCopy* copy = e->getNode(node);
    assert(copy != 0);
    _ready = copy->ready();
    _trusted = copy->trusted();
    _active = copy->active();
    for (uint32_t i=0; i<idealState.size(); ++i) {
        if (idealState[i] == node) {
            _ideal = i;
            break;
        }
    }
}

vespalib::string
ActiveCopy::getReason() const {
    if (_ready && _trusted && _ideal < 0xffff) {
        vespalib::asciistream ost;
        ost << "copy is ready, trusted and ideal state priority " << _ideal;
        return ost.str();
    } else if (_ready && _trusted) {
        return "copy is ready and trusted";
    } else if (_ready) {
        return "copy is ready";
    } else if (_trusted && _ideal < 0xffff) {
        vespalib::asciistream ost;
        ost << "copy is trusted and ideal state priority " << _ideal;
        return ost.str();
    } else if (_trusted) {
        return "copy is trusted";
    } else if (_ideal < 0xffff) {
        vespalib::asciistream ost;
        ost << "copy is ideal state priority " << _ideal;
        return ost.str();
    } else {
        return "first available copy";
    }
}

std::ostream&
operator<<(std::ostream& out, const ActiveCopy & e) {
    out << "Entry(Node " << e._nodeIndex;
    if (e._ready) out << ", ready";
    if (e._trusted) out << ", trusted";
    if (e._ideal < 0xffff) out << ", ideal pri " << e._ideal;
    out << ")";
    return out;
}

namespace {

    struct ActiveStateOrder {
        bool operator()(const ActiveCopy & e1, const ActiveCopy & e2) {
            if (e1._ready != e2._ready) return e1._ready;
            if (e1._trusted != e2._trusted) return e1._trusted;
            if (e1._ideal != e2._ideal) return e1._ideal < e2._ideal;
            if (e1._active != e2._active) return e1._active;
            return e1._nodeIndex < e2._nodeIndex;
        }
    };

    void buildValidNodeIndexList(BucketDatabase::Entry& e, std::vector<uint16_t>& result) {
        for (uint32_t i=0, n=e->getNodeCount(); i < n; ++i) {
            const BucketCopy& cp = e->getNodeRef(i);
            if (!cp.valid()) continue;
            result.push_back(cp.getNode());
        }
    }

    void buildNodeList(BucketDatabase::Entry& e,
                       const std::vector<uint16_t>& nodeIndexes,
                       const std::vector<uint16_t>& idealState,
                       std::vector<ActiveCopy>& result)
    {
        result.reserve(nodeIndexes.size());
        for (uint16_t nodeIndex : nodeIndexes) {
            result.emplace_back(nodeIndex, e, idealState);
        }
    }
}

#undef DEBUG
#if 0
#define DEBUG(a) a
#else
#define DEBUG(a)
#endif

ActiveList
ActiveCopy::calculate(const std::vector<uint16_t>& idealState,
                      const lib::Distribution& distribution,
                      BucketDatabase::Entry& e)
{
    DEBUG(std::cerr << "Ideal state is " << idealState << "\n");
    std::vector<uint16_t> validNodesWithCopy;
    buildValidNodeIndexList(e, validNodesWithCopy);
    if (validNodesWithCopy.empty()) {
        return ActiveList();
    }
    typedef std::vector<uint16_t> IndexList;
    std::vector<IndexList> groups;
    if (distribution.activePerGroup()) {
        groups = distribution.splitNodesIntoLeafGroups(std::move(validNodesWithCopy));
    } else {
        groups.push_back(std::move(validNodesWithCopy));
    }
    std::vector<ActiveCopy> result;
    result.reserve(groups.size());
    for (uint32_t i=0; i<groups.size(); ++i) {
        std::vector<ActiveCopy> entries;
        buildNodeList(e, groups[i], idealState, entries);
        DEBUG(std::cerr << "Finding active for group " << entries << "\n");
        auto best = std::min_element(entries.begin(), entries.end(), ActiveStateOrder());
        DEBUG(std::cerr << "Best copy " << *best << "\n");
        result.emplace_back(*best);
    }
    return ActiveList(std::move(result));
}

void
ActiveList::print(std::ostream& out, bool verbose,
                  const std::string& indent) const
{
    out << "[";
    if (verbose) {
        for (size_t i=0; i<_v.size(); ++i) {
            out << "\n" << indent << "  "
                << _v[i]._nodeIndex << " " << _v[i].getReason();
        }
        if (!_v.empty()) out << "\n" << indent;
    } else {
        if (!_v.empty()) out << _v[0]._nodeIndex;
        for (size_t i=1; i<_v.size(); ++i) {
            out << " " << _v[i]._nodeIndex;
        }
    }
    out << "]";
}

bool
ActiveList::contains(uint16_t node) const
{
    for (const auto & candadate : _v) {
        if (node == candadate._nodeIndex) return true;
    }
    return false;
}

}
