// R1 codec probe / agent selftest. Encodes, with the agent's own encoders, the
// E2SM-KPM pieces that no gate exercised before (RAN function description with
// two report styles, header, format 1 with INTEGER/REAL/noValue, format 2 with
// en-gNB-UEIDs) plus the agent's E2AP PDUs, and writes them as hex for decoding
// with kpimon's own library (tools/kpimon-decode-harness) and tshark. It also
// checks the KPM UE IDs of both node kinds built from ueContext lines
// (codec-probe-kpm-ue-id.cpp) and the E2AP PDUs (codec-probe-e2ap.cpp); any
// failed check makes it exit 1.
//
// usage: codec-probe <metric-map.json> <out-dir>
//   <out-dir>/ind-lines.txt   "<id> <hdr_hex> <msg_hex>" per indication piece
//   <out-dir>/ranfunc.txt     "<id> <ranfunction_description_hex>" (id ranfunc: gNB lists; ranfunc-enb: eNB lists)
//   <out-dir>/expect.json     expected records (REAL as IEEE-754 bits) and lists
//   <out-dir>/e2ap-<name>.hex E2AP PDUs (see codec-probe-e2ap.cpp)
//   <out-dir>/f2-*.xer        decoded Format 2 messages with en-gNB-UEID / eNB-UEID
#include <cinttypes>
#include <cmath>
#include <cstdio>
#include <array>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "../src/kpm-encoder.hpp"
#include "../src/metric-map.hpp"

using namespace agent;
using nlohmann::json;

int probe_e2ap(const std::string &outDir, const Bytes &ranFuncDef, const Bytes &enbRanFuncDef);  // codec-probe-e2ap.cpp
int probe_kpm_ue_ids(const std::string &outDir, const std::string &mapPath, const Bytes &hdr);  // codec-probe-kpm-ue-id.cpp

namespace {

MeasValue I(unsigned long v) { MeasValue m; m.kind = MeasValue::Integer; m.integer = v; return m; }
MeasValue R(double v) { MeasValue m; m.kind = MeasValue::Real; m.real = v; return m; }
MeasValue N() { return MeasValue{}; }

json expect_records(const std::vector<MeasValue> &recs) {
  json a = json::array();
  for (const MeasValue &v : recs) {
    if (v.kind == MeasValue::Integer) a.push_back({{"t", "int"}, {"v", v.integer}});
    else if (v.kind == MeasValue::Real) {
      uint64_t bits;
      memcpy(&bits, &v.real, 8);
      char b[32];
      snprintf(b, sizeof b, "%016" PRIx64, bits);
      a.push_back({{"t", "real"}, {"bits", b}});
    } else a.push_back({{"t", "none"}});
  }
  return a;
}

bool fail(const std::string &what, const std::string &err) {
  fprintf(stderr, "codec-probe: %s: %s\n", what.c_str(), err.c_str());
  return false;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s <metric-map.json> <out-dir>\n", argv[0]);
    return 2;
  }
  std::string dir = argv[2], err;
  MetricMap map;
  if (!load_metric_map(argv[1], "gnb", map, err)) return fail("metric map", err), 1;

  // (a) RAN function description from the real gNB lists.
  RanFunctionNames names;
  names.oid = "1.3.6.1.4.1.53148.1.3.2.2";
  names.description = "ns-O-RAN KPM map v1 " + map.sha256.substr(0, 8);
  Bytes def;
  if (!encode_ran_function_description(names, map.cell, map.ue, def, err)) return fail("ranfunc", err), 1;
  // and from the eNB lists (an eNB agent loads the rows of kind enb), for the eNB E2 Setup Request
  MetricMap enbMap;
  Bytes enbDef;
  if (!load_metric_map(argv[1], "enb", enbMap, err)) return fail("metric map enb", err), 1;
  if (!encode_ran_function_description(names, enbMap.cell, enbMap.ue, enbDef, err)) return fail("ranfunc enb", err), 1;

  // (b) header: 2026-10-22T00:00:00.123Z.
  Bytes hdr;
  auto ts = ntp64_from_unix_ms(1792627200123LL);
  if (!encode_indication_header(ts, "ns3-cell-2", kSenderType, kVendorName, hdr, err)) return fail("header", err), 1;

  // (c) format 1 over the full cell list: INTEGER, REAL (edge doubles), noValue.
  const double dbl[] = {0.1, -0.0, 0.0, 9007199254740992.0, 1e300, -1e300, 5e-324, 2.2250738585072014e-308,
                        1.7976931348623157e308, -1.5, 123456.789, 1.0 / 3.0, -273.15, 1e-10, M_PI};
  std::vector<MeasValue> f1 = {I(0), I(1), I(42), I(2147483647)};
  for (double d : dbl) f1.push_back(R(d));
  f1.push_back(N()); f1.push_back(N()); f1.push_back(N());
  while (f1.size() < map.cell.size()) f1.push_back(I(f1.size()));
  Bytes m1;
  if (!encode_format1({f1}, map.cell, 100, m1, err)) return fail("format1", err), 1;

  // (d) format 2, 3 metrics x 2 UEs, with and without UE IDs: en-gNB-UEIDs of
  // master eNB 1, m-eNB-UE-X2AP-ID 2 and the upper bound 4095.
  std::vector<MetricRow> three(map.ue.begin(), map.ue.begin() + 3);
  std::vector<std::vector<MeasValue>> ues2 = {{I(2), R(0.1), N()}, {I(7), R(-0.0), R(1e300)}};
  auto en_gnb_ue = [](uint32_t x2ap) {
    KpmUeId u;
    u.mEnbUeX2apId = x2ap;
    u.macroEnbId = 1;
    return u;
  };
  std::vector<KpmUeId> ids2 = {en_gnb_ue(2), en_gnb_ue(4095)};
  const std::array<uint8_t, 3> plmn = {0x00, 0xF1, 0x10};
  Bytes m2a, m2b, m2full;
  if (!encode_format2({ues2}, ids2, three, plmn, true, 100, m2a, err)) return fail("format2 ueid", err), 1;
  if (!encode_format2({ues2}, ids2, three, plmn, false, 100, m2b, err)) return fail("format2 no ueid", err), 1;

  // (e) format 2 over the full 58-entry UE list x 4 UEs (realistic size).
  std::vector<std::vector<MeasValue>> ues4;
  std::vector<KpmUeId> ids4 = {en_gnb_ue(1), en_gnb_ue(2), en_gnb_ue(3), en_gnb_ue(4)};
  for (int u = 0; u < 4; u++) {
    std::vector<MeasValue> r;
    for (size_t k = 0; k < map.ue.size(); k++)
      r.push_back(map.ue[k].type == RecordType::Integer ? I(1000 * u + k) : R(u + k / 7.0 - 3.25));
    ues4.push_back(r);
  }
  if (!encode_format2({ues4}, ids4, map.ue, plmn, true, 100, m2full, err)) return fail("format2 full", err), 1;

  {
    std::ofstream lines(dir + "/ind-lines.txt");
    lines << "f1 " << to_hex(hdr) << " " << to_hex(m1) << "\n";
    lines << "f2ueid " << to_hex(hdr) << " " << to_hex(m2a) << "\n";
    lines << "f2noueid " << to_hex(hdr) << " " << to_hex(m2b) << "\n";
    lines << "f2full " << to_hex(hdr) << " " << to_hex(m2full) << "\n";
  }
  std::ofstream(dir + "/ranfunc.txt") << "ranfunc " << to_hex(def) << "\n" << "ranfunc-enb " << to_hex(enbDef) << "\n";

  auto metric_major = [](const std::vector<std::vector<MeasValue>> &u) {
    std::vector<MeasValue> out;
    for (size_t m = 0; m < u[0].size(); m++)
      for (size_t k = 0; k < u.size(); k++) out.push_back(u[k][m]);
    return out;
  };
  json cellNames = json::array(), ueNames = json::array();
  for (auto &r : map.cell) cellNames.push_back(r.kpm);
  for (auto &r : map.ue) ueNames.push_back(r.kpm);
  json ex = {{"ranfunc", {{"cell", cellNames}, {"ue", ueNames}, {"description", names.description}}},
             {"header_ts_hex", to_hex(Bytes(ts.begin(), ts.end()))},
             {"f1", expect_records(f1)},
             {"f2ueid", expect_records(metric_major(ues2))},
             {"f2noueid", expect_records(metric_major(ues2))},
             {"f2full", expect_records(metric_major(ues4))},
             {"sizes", {{"ranfunc", def.size()}, {"hdr", hdr.size()}, {"f1", m1.size()}, {"f2ueid", m2a.size()},
                        {"f2noueid", m2b.size()}, {"f2full", m2full.size()}}},
             {"map_sha256", map.sha256}};
  std::ofstream(dir + "/expect.json") << ex.dump(1) << "\n";
  printf("%s\n", ex["sizes"].dump().c_str());
  int ueIdRc = probe_kpm_ue_ids(dir, argv[1], hdr);  // appends f2engnb and f2enb to ind-lines.txt
  int e2apRc = probe_e2ap(dir, def, enbDef);
  return ueIdRc || e2apRc ? 1 : 0;
}
