// Metric map loading and sample-value conversion (see metric-map.hpp).
#include "metric-map.hpp"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>

#include "sha256.hpp"

namespace agent {

using nlohmann::json;

namespace {

constexpr double kInt32Max = 2147483647.0;

bool split_pointer(const std::string &p, std::vector<std::string> &out) {
  out.clear();
  if (p.empty() || p[0] != '/') return false;
  std::string tok;
  for (size_t i = 1; i <= p.size(); i++) {
    if (i == p.size() || p[i] == '/') {
      out.push_back(tok);
      tok.clear();
    } else if (p[i] == '~' && i + 1 < p.size() && (p[i + 1] == '0' || p[i + 1] == '1')) {
      tok += p[i + 1] == '0' ? '~' : '/';
      i++;
    } else {
      tok += p[i];
    }
  }
  return true;
}

bool parse_row(const json &r, MetricRow &row, std::string &err) {
  try {
    row.order = r.at("order").get<int>();
    row.measId = r.at("measId").get<long>();
    row.kpm = r.at("kpm").get<std::string>();
    std::string t = r.at("type").get<std::string>();
    std::string s = r.at("scope").get<std::string>();
    std::string x = r.at("xform").get<std::string>();
    row.src = r.at("src").get<std::string>();
    if (t != "INTEGER" && t != "REAL") throw std::runtime_error("type " + t);
    if (s != "sample" && s != "ue") throw std::runtime_error("scope " + s);
    if (x != "none" && x != "ns_to_ms_floor") throw std::runtime_error("xform " + x);
    row.type = t == "INTEGER" ? RecordType::Integer : RecordType::Real;
    row.scope = s == "ue" ? Scope::Ue : Scope::Sample;
    row.xform = x == "ns_to_ms_floor" ? Xform::NsToMsFloor : Xform::None;
    if (!split_pointer(row.src, row.srcTokens)) throw std::runtime_error("src " + row.src);
  } catch (const std::exception &e) {
    err = std::string("bad row: ") + e.what() + " in " + r.dump();
    return false;
  }
  return true;
}

bool finish_list(std::vector<MetricRow> &rows, const char *name, std::string &err) {
  std::sort(rows.begin(), rows.end(), [](const MetricRow &a, const MetricRow &b) { return a.order < b.order; });
  if (rows.empty()) {
    err = std::string("list ") + name + " is empty (kpimon divides by its length)";
    return false;
  }
  for (size_t i = 0; i < rows.size(); i++)
    if (rows[i].order != (int)i + 1) {
      err = std::string("list ") + name + ": order must be 1..n without gaps";
      return false;
    }
  return true;
}

}  // namespace

bool parse_metric_map(const std::string &bytes, const std::string &kind, MetricMap &map, std::string &err) {
  json doc = json::parse(bytes, nullptr, false);
  if (doc.is_discarded() || !doc.is_object() || !doc.contains("rows") || !doc["rows"].is_array()) {
    err = "metric map is not a JSON object with a rows array";
    return false;
  }
  map = MetricMap{};
  map.sha256 = sha256_hex(bytes);
  for (const json &r : doc["rows"]) {
    if (!r.is_object() || r.value("kind", "") != kind) continue;
    MetricRow row;
    if (!parse_row(r, row, err)) return false;
    std::string list = r.value("list", "");
    if (list == "cell") map.cell.push_back(row);
    else if (list == "ue") map.ue.push_back(row);
    else {
      err = "bad list in row " + r.dump();
      return false;
    }
  }
  return finish_list(map.cell, "cell", err) && finish_list(map.ue, "ue", err);
}

bool load_metric_map(const std::string &path, const std::string &kind, MetricMap &map, std::string &err) {
  std::ifstream f(path, std::ios::binary);
  if (!f) {
    err = "cannot open " + path;
    return false;
  }
  std::stringstream ss;
  ss << f.rdbuf();
  return parse_metric_map(ss.str(), kind, map, err);
}

const json *resolve_pointer(const json &root, const std::vector<std::string> &tokens) {
  const json *cur = &root;
  for (const std::string &t : tokens) {
    if (cur->is_object()) {
      auto it = cur->find(t);
      if (it == cur->end()) return nullptr;
      cur = &*it;
    } else if (cur->is_array()) {
      if (t.empty() || t.find_first_not_of("0123456789") != std::string::npos) return nullptr;
      size_t idx = std::stoul(t);
      if (idx >= cur->size()) return nullptr;
      cur = &(*cur)[idx];
    } else {
      return nullptr;
    }
  }
  return cur;
}

MeasValue convert_value(const json *v, const MetricRow &row, ConvCounters &c) {
  MeasValue out;
  if (!v || v->is_null()) return out;  // absent or non-finite in ns-3: noValue
  if (!v->is_number() || v->is_boolean()) {
    c.typeMismatch++;
    return out;
  }
  if (row.type == RecordType::Real) {
    out.kind = MeasValue::Real;
    if (v->is_number_float()) {
      out.real = v->get<double>();
    } else if (v->is_number_unsigned()) {
      uint64_t u = v->get<uint64_t>();
      out.real = (double)u;
      if (out.real >= 18446744073709551616.0 || (uint64_t)out.real != u) c.realInexact++;
    } else {
      int64_t s = v->get<int64_t>();
      out.real = (double)s;
      if (out.real >= 9223372036854775808.0 || (int64_t)out.real != s) c.realInexact++;
    }
    if (row.xform == Xform::NsToMsFloor) out.real = std::floor(out.real / 1e6);
    return out;
  }
  // INTEGER rows: exact integral value in 0..2^31-1, otherwise noValue.
  double d;
  if (v->is_number_float()) {
    d = v->get<double>();
    if (d != std::floor(d)) {
      c.typeMismatch++;
      return out;
    }
  } else if (v->is_number_unsigned()) {
    uint64_t u = v->get<uint64_t>();
    if (row.xform == Xform::NsToMsFloor) u /= 1000000u;
    if (u > 2147483647u) {
      c.int32Overflow++;
      return out;
    }
    out.kind = MeasValue::Integer;
    out.integer = (unsigned long)u;
    return out;
  } else {
    int64_t s = v->get<int64_t>();
    if (row.xform == Xform::NsToMsFloor) s = s >= 0 ? s / 1000000 : -((-s + 999999) / 1000000);
    if (s < 0 || s > 2147483647) {
      c.int32Overflow++;
      return out;
    }
    out.kind = MeasValue::Integer;
    out.integer = (unsigned long)s;
    return out;
  }
  if (row.xform == Xform::NsToMsFloor) d = std::floor(d / 1e6);
  if (d < 0 || d > kInt32Max) {
    c.int32Overflow++;
    return out;
  }
  out.kind = MeasValue::Integer;
  out.integer = (unsigned long)d;
  return out;
}

std::vector<MeasValue> build_records(const std::vector<MetricRow> &rows, const json &sample, const json *ue,
                                     ConvCounters &c) {
  std::vector<MeasValue> rec;
  rec.reserve(rows.size());
  for (const MetricRow &row : rows) {
    const json *root = row.scope == Scope::Ue ? ue : &sample;
    const json *v = root ? resolve_pointer(*root, row.srcTokens) : nullptr;
    rec.push_back(convert_value(v, row, c));
  }
  return rec;
}

}  // namespace agent
