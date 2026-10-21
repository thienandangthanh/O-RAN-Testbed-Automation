// The metric map (schema/metric-map.v1.json): which IPC sample value becomes
// which E2SM-KPM measurement, in which list, at which position and with which
// record type. The map is the single authority shared by the agent and the
// M6 gate; the agent fingerprints the file bytes (sha256) and advertises sha8.
#ifndef NS3_E2_AGENT_METRIC_MAP_HPP
#define NS3_E2_AGENT_METRIC_MAP_HPP

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace agent {

enum class RecordType { Integer, Real };
enum class Xform { None, NsToMsFloor };
enum class Scope { Sample, Ue };

struct MetricRow {
  int order = 0;
  long measId = 0;
  std::string kpm;                  // KPM measName (PrintableString-legal)
  RecordType type = RecordType::Real;
  Scope scope = Scope::Sample;
  std::string src;                  // JSON pointer, relative to the sample or the UE object
  std::vector<std::string> srcTokens;  // pre-split, unescaped pointer tokens
  Xform xform = Xform::None;
};

// One KPM measurement record value as it goes on the wire.
struct MeasValue {
  enum Kind { NoValue, Integer, Real } kind = NoValue;
  unsigned long integer = 0;
  double real = 0.0;
};

// Conversion counters exported in the stats line.
struct ConvCounters {
  uint64_t int32Overflow = 0;  // INTEGER row value outside 0..2^31-1 -> noValue
  uint64_t typeMismatch = 0;   // value of the wrong JSON type for the row -> noValue
  uint64_t realInexact = 0;    // integer that does not round-trip through double
};

struct MetricMap {
  std::string sha256;              // of the file bytes
  std::vector<MetricRow> cell;     // list "cell" for the selected kind, by order
  std::vector<MetricRow> ue;       // list "ue" for the selected kind, by order
};

// Loads the rows of `kind` from `path`. Returns false and sets `err` on any
// structural problem (missing field, bad type, non-contiguous order, empty list).
bool load_metric_map(const std::string &path, const std::string &kind, MetricMap &map, std::string &err);

// Same, from already-read file bytes (used by the codec probe).
bool parse_metric_map(const std::string &bytes, const std::string &kind, MetricMap &map, std::string &err);

// Resolves a pre-split JSON pointer; returns nullptr when any step is missing.
const nlohmann::json *resolve_pointer(const nlohmann::json &root, const std::vector<std::string> &tokens);

// Converts one JSON value (nullptr = absent) for `row` into a record value.
MeasValue convert_value(const nlohmann::json *v, const MetricRow &row, ConvCounters &c);

// Builds the record vector of one list for a sample (and, for UE rows, a UE).
std::vector<MeasValue> build_records(const std::vector<MetricRow> &rows, const nlohmann::json &sample,
                                     const nlohmann::json *ue, ConvCounters &c);

}  // namespace agent

#endif
