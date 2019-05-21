// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#pragma once

#include <vespa/searchlib/fef/handle.h>
#include <vespa/searchlib/fef/match_data_details.h>
#include <vespa/vespalib/stllike/hash_set.h>
#include <vespa/vespalib/util/noncopyable.hpp>

namespace proton::matching {

/**
 * This is a recorder that will register all handles used by any features for a given query.
 * It is activated using thread locals by using the Binder.
 * In order to ensure that no handles goes by unnoticed and asserter is added. It should typically have the
 * same lifespan as the recorder itself.
 * After the Binders has gone out of scope this recorder has a list of all feature handles that might be
 * by this query. This can then be used to avoid a lot of unpacking of data.
 */
class HandleRecorder
{
public:
    using HandleSet = vespalib::hash_set<search::fef::TermFieldHandle>;
    class Binder : public vespalib::noncopyable {
    public:
        Binder(HandleRecorder & recorder);
        ~Binder();
    };
    class Asserter : public vespalib::noncopyable {
    public:
        Asserter();
        ~Asserter();
    };
    HandleRecorder();
    ~HandleRecorder();
    const HandleSet& get_normal_handles() const { return _normal_handles; }
    const HandleSet& get_cheap_handles() const { return _cheap_handles; }
    static void register_handle(search::fef::TermFieldHandle handle,
                                search::fef::MatchDataDetails requested_details);
    vespalib::string to_string() const;
private:
    void add(search::fef::TermFieldHandle handle,
             search::fef::MatchDataDetails requested_details);
    HandleSet _normal_handles;
    HandleSet _cheap_handles;
};

}

