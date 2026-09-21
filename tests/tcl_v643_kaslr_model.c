#include <stdint.h>
#include <stdio.h>

#include "tcl_v643/compat_select_geometry.h"

static int fail(const char *message) {
  fprintf(stderr, "FAIL: %s\n", message);
  return 1;
}

int main(void) {
  /* Use an arbitrary 2 MiB-aligned slide and representative syscall-entry
   * samples.  This is a coordinate model, not a perf sampler. */
  const uint64_t slide = UINT64_C(0x0000001720000000);
  const uint64_t runtime_text = TCL_V643_KIMAGE_TEXT_BASE + slide;
  const uint64_t sample_first = runtime_text +
                                TCL_V643_ENTRY_TEXT_START_OFF + 0x40;
  const uint64_t sample_last = runtime_text +
                               TCL_V643_ENTRY_TEXT_END_OFF - 4;
  const uint64_t negative_distance = UINT64_C(0x04800000);
  const uint64_t runtime_text_below =
      TCL_V643_KIMAGE_TEXT_BASE - negative_distance;
  const uint64_t sample_below = runtime_text_below +
                                TCL_V643_ENTRY_TEXT_START_OFF + 0x40;
  const uint64_t mask = ~(TCL_V643_KASLR_IMAGE_ALIGNMENT - 1);

  if ((TCL_V643_KIMAGE_TEXT_BASE &
       (TCL_V643_KASLR_IMAGE_ALIGNMENT - 1)) != 0)
    return fail("link-time _text is not 2 MiB aligned");
  if ((slide & (TCL_V643_KASLR_IMAGE_ALIGNMENT - 1)) != 0)
    return fail("test slide is not 2 MiB aligned");
  if (TCL_V643_ENTRY_TEXT_END_OFF >= TCL_V643_KASLR_IMAGE_ALIGNMENT)
    return fail("entry text escapes the first KASLR image block");
  if ((sample_first & mask) != runtime_text ||
      (sample_last & mask) != runtime_text)
    return fail("entry-text perf sample does not recover runtime _text");
  if ((negative_distance & (TCL_V643_KASLR_IMAGE_ALIGNMENT - 1)) != 0 ||
      (sample_below & mask) != runtime_text_below)
    return fail("negative KASLR slide is not accepted/recovered");

  printf("entry text: _text+%#llx..+%#llx\n",
         (unsigned long long)TCL_V643_ENTRY_TEXT_START_OFF,
         (unsigned long long)TCL_V643_ENTRY_TEXT_END_OFF);
  printf("sample block mask: %#llx -> runtime _text %#llx\n",
         (unsigned long long)mask,
         (unsigned long long)(sample_first & mask));
  printf("negative slide: -%#llx -> runtime _text %#llx\n",
         (unsigned long long)negative_distance,
         (unsigned long long)(sample_below & mask));
  puts("PASS: a V643 syscall-entry kernel IP determines the 2 MiB KASLR base");
  return 0;
}
