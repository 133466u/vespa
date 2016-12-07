// Copyright 2016 Yahoo Inc. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
#include <vespa/fastos/fastos.h>
#include <vespa/log/log.h>
LOG_SETUP(".features.fieldtermmatchfeature");

#include <vespa/searchlib/fef/featurenamebuilder.h>
#include <vespa/searchlib/fef/fieldinfo.h>
#include <vespa/searchlib/fef/fieldtype.h>
#include <vespa/searchlib/fef/properties.h>
#include <vespa/searchlib/fef/itermdata.h>
#include <vespa/vespalib/util/stringfmt.h>
#include "fieldtermmatchfeature.h"
#include "utils.h"

namespace search {
namespace features {

FieldTermMatchExecutor::FieldTermMatchExecutor(const search::fef::IQueryEnvironment &env,
                                               uint32_t fieldId, uint32_t termId) :
    search::fef::FeatureExecutor(),
    _fieldHandle(util::getTermFieldHandle(env, termId, fieldId))
{
}

void
FieldTermMatchExecutor::execute(search::fef::MatchData &match)
{
    if (_fieldHandle == search::fef::IllegalHandle) {
        outputs().set_number(0, 1000000); // firstPosition
        outputs().set_number(1, 1000000); // lastPosition
        outputs().set_number(2, 0.0f); // occurrences
        outputs().set_number(3, 0.0f); // sum weight
        outputs().set_number(4, 0.0f); // avg exactness
        return;
    }

    search::fef::TermFieldMatchData &tfmd = *match.resolveTermField(_fieldHandle);
    uint32_t firstPosition = 1000000;
    uint32_t lastPosition = 1000000;
    uint32_t occurrences = 0;
    double sumExactness = 0;
    int64_t weight = 0;
    if (tfmd.getDocId() == match.getDocId()) {
        search::fef::FieldPositionsIterator it = tfmd.getIterator();
        if (it.valid()) {
            lastPosition = 0;
            while (it.valid()) {
                firstPosition = std::min(firstPosition, it.getPosition());
                lastPosition = std::max(lastPosition, it.getPosition());
                ++occurrences;
                weight += it.getElementWeight();
                sumExactness += it.getMatchExactness();
                it.next();
            }
        } else {
            lastPosition = 1000000;
            occurrences = 1;
        }
    }
    outputs().set_number(0, firstPosition);
    outputs().set_number(1, lastPosition);
    outputs().set_number(2, occurrences);
    outputs().set_number(3, weight);
    outputs().set_number(4, (occurrences > 0) ? (sumExactness / occurrences) : 0);
}

FieldTermMatchBlueprint::FieldTermMatchBlueprint() :
    search::fef::Blueprint("fieldTermMatch"),
    _fieldId(0),
    _termId(0)
{
    // empty
}

void
FieldTermMatchBlueprint::visitDumpFeatures(const search::fef::IIndexEnvironment &env,
                                           search::fef::IDumpFeatureVisitor &visitor) const
{
    const search::fef::Properties &props = env.getProperties();
    const vespalib::string &baseName = getBaseName();
    int baseNumTerms = atoi(props.lookup(baseName, "numTerms").get("5").c_str());

    for (uint32_t i = 0; i < env.getNumFields(); ++i) {
        const search::fef::FieldInfo& field = *env.getField(i);
        if (field.type() == search::fef::FieldType::INDEX) {
            const vespalib::string &fieldName = field.name();
            const search::fef::Property &prop = props.lookup(baseName, "numTerms", fieldName);
            int numTerms = prop.found() ? atoi(prop.get().c_str()) : baseNumTerms;
            for (int term = 0; term < numTerms; ++term) {
                search::fef::FeatureNameBuilder fnb;
                fnb.baseName(baseName)
                    .parameter(fieldName)
                    .parameter(vespalib::make_string("%d", term));
                visitor.visitDumpFeature(fnb.output("firstPosition").buildName());
                visitor.visitDumpFeature(fnb.output("occurrences").buildName());
                visitor.visitDumpFeature(fnb.output("weight").buildName());
            }
         }
    }
}

bool
FieldTermMatchBlueprint::setup(const search::fef::IIndexEnvironment &env,
                               const search::fef::ParameterList &params)
{
    _fieldId = params[0].asField()->id();
    _termId = params[1].asInteger();
    describeOutput("firstPosition", "The first occurrence of this term.");
    describeOutput("lastPosition",  "The last occurrence of this term.");
    describeOutput("occurrences",  "The number of occurrence of this term.");
    describeOutput("weight", "The sum occurence weights of this term.");
    describeOutput("exactness", "The average exactness this term.");
    env.hintFieldAccess(_fieldId);
    return true;
}

search::fef::Blueprint::UP
FieldTermMatchBlueprint::createInstance() const
{
    return search::fef::Blueprint::UP(new FieldTermMatchBlueprint());
}

search::fef::FeatureExecutor &
FieldTermMatchBlueprint::createExecutor(const search::fef::IQueryEnvironment &env, vespalib::Stash &stash) const
{
    return stash.create<FieldTermMatchExecutor>(env, _fieldId, _termId);
}

}}
