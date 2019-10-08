// Copyright 2019 Oath Inc. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#include "struct_fields_resolver.h"
#include <vespa/searchlib/attribute/iattributemanager.h>
#include <vespa/searchlib/common/struct_field_mapper.h>
#include <algorithm>

#include <vespa/log/log.h>
LOG_SETUP(".searchsummary.docsummary.struct_fields_resolver");

using search::attribute::CollectionType;

namespace search::docsummary {

StructFieldsResolver::StructFieldsResolver(const vespalib::string& field_name, const IAttributeManager& attr_mgr)
    : _field_name(field_name),
      _map_key_attribute(),
      _map_value_fields(),
      _map_value_attributes(),
      _array_fields(),
      _array_attributes(),
      _has_map_key(false),
      _error(false)
{
    std::vector<const search::attribute::IAttributeVector *> attrs;
    auto attr_ctx = attr_mgr.createContext();
    attr_ctx->getAttributeList(attrs);
    vespalib::string prefix = field_name + ".";
    _map_key_attribute = prefix + "key";
    vespalib::string value_prefix = prefix + "value.";
    for (const auto attr : attrs) {
        vespalib::string name = attr->getName();
        if (name.substr(0, prefix.size()) != prefix) {
            continue;
        }
        if (attr->getCollectionType() != CollectionType::Type::ARRAY) {
            LOG(warning, "Attribute '%s' is not an array attribute", name.c_str());
            _error = true;
            break;
        }
        if (name.substr(0, value_prefix.size()) == value_prefix) {
            _map_value_fields.emplace_back(name.substr(value_prefix.size()));
        } else {
            _array_fields.emplace_back(name.substr(prefix.size()));
            if (name == _map_key_attribute) {
                _has_map_key = true;
            }
        }
    }
    if (!_error) {
        std::sort(_map_value_fields.begin(), _map_value_fields.end());
        for (const auto& field : _map_value_fields) {
            _map_value_attributes.emplace_back(value_prefix + field);
        }

        std::sort(_array_fields.begin(), _array_fields.end());
        for (const auto& field : _array_fields) {
            _array_attributes.emplace_back(prefix + field);
        }

        if (!_map_value_fields.empty()) {
            if (!_has_map_key) {
                LOG(warning, "Missing key attribute '%s', have value attributes for map", _map_key_attribute.c_str());
                _error = true;
            } else if (_array_fields.size() != 1u) {
                LOG(warning, "Could not determine if field '%s' is array or map of struct", field_name.c_str());
                _error = true;
            }
        }
    }
}

StructFieldsResolver::~StructFieldsResolver() = default;

void
StructFieldsResolver::apply_to(StructFieldMapper& mapper) const
{
    if (is_map_of_struct()) {
        mapper.add_mapping(_field_name, _map_key_attribute);
        for (const auto& sub_field : _map_value_attributes) {
            mapper.add_mapping(_field_name, sub_field);
        }
    } else {
        for (const auto& sub_field : _array_attributes) {
            mapper.add_mapping(_field_name, sub_field);
        }
    }
}

}

