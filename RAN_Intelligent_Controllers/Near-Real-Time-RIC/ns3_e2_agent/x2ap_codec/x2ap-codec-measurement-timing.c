/* MeasurementTimingConfiguration of the X2AP codec (see x2ap-codec.h). 3GPP TS 38.331 defines it in UPER and this
 * library's asn1c output is X2AP only, so the fixed shape below is written bit by bit (X.691: constrained whole
 * numbers in the minimum number of bits, CHOICE indices and ENUMERATED values as constrained whole numbers, one
 * presence bit per OPTIONAL component, one extension bit for an extensible SEQUENCE; the outermost value padded to
 * an octet). Cross-checked against pycrate (tools/asn1-indep). */
#include <stdlib.h>
#include <string.h>

#include "x2ap-codec-internal.h"

typedef struct {
  uint8_t *b;
  size_t cap, bit;
} bitw;

static int put(bitw *w, uint32_t v, int n) {
  for (int i = n - 1; i >= 0; i--, w->bit++) {
    if (w->bit / 8 >= w->cap) return -1;
    if ((v >> i) & 1) w->b[w->bit / 8] |= (uint8_t)(0x80 >> (w->bit % 8));
  }
  return 0;
}

int x2c_measurement_timing_configuration(long arfcn, int scs, int period_sf, int offset, int duration_sf,
                                         uint8_t out[8], size_t *out_len, char *err, size_t err_len) {
  static const int periods[] = {5, 10, 20, 40, 80, 160};
  static const int offset_bits[] = {3, 4, 5, 6, 7, 8};  // INTEGER (0..period-1)
  int p = -1;
  for (int i = 0; i < 6; i++)
    if (periods[i] == period_sf) p = i;
  if (arfcn < 0 || arfcn > 3279165 || scs < 0 || scs > 7 || p < 0 || offset < 0 || offset >= period_sf ||
      duration_sf < 1 || duration_sf > 5)
    return x2c_fail(err, err_len, "MTC: value out of range");
  memset(out, 0, 8);
  bitw w = {out, 8, 0};
  int bad = put(&w, 0, 1)                    // criticalExtensions: c1 (index 0 of 2)
            || put(&w, 0, 2)                 // c1: measTimingConf (index 0 of 4)
            || put(&w, 0x2, 2)               // MeasurementTimingConfiguration-IEs: measTiming present, no extension
            || put(&w, 0, 5)                 // MeasTimingList SIZE (1..32): one MeasTiming
            || put(&w, 0, 1)                 // MeasTiming: extension bit (no extension additions)
            || put(&w, 1, 1)                 // MeasTiming: frequencyAndTiming present
            || put(&w, 0, 1)                 // frequencyAndTiming: no ss-RSSI-Measurement
            || put(&w, (uint32_t)arfcn, 22)  // carrierFreq ARFCN-ValueNR (0..3279165)
            || put(&w, (uint32_t)scs, 3)     // ssbSubcarrierSpacing (8 values)
            || put(&w, (uint32_t)p, 3)       // periodicityAndOffset (6 alternatives)
            || put(&w, (uint32_t)offset, offset_bits[p])
            || put(&w, (uint32_t)(duration_sf - 1), 3);  // duration ENUMERATED {sf1..sf5}
  if (bad) return x2c_fail(err, err_len, "MTC: buffer too small");
  *out_len = (w.bit + 7) / 8;
  return 0;
}

void x2c_free(void *p) { free(p); }
