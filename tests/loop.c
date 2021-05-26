#include <stdint.h>

int main() {
  uint32_t i = UINT32_MAX;
  __asm__ volatile (
          "   nop \n" /* dummy */
          "1: subs %[input], %[input], #1 \n" /* decrement register */
          "   nop \n" /* avoid overflow */
          "   nop \n" /* avoid overflow */
          "   nop \n" /* avoid overflow */
          "   nop \n" /* avoid overflow */
          "   nop \n" /* avoid overflow */
          "   nop \n" /* avoid overflow */
          "   nop \n" /* avoid overflow */
          "   nop \n" /* avoid overflow */
          "   bne 1b \n" /* if not zero, loop */
          "   nop \n" /* dummy */
          :
          : [input] "r" (i)
          : );
  return 0;
}
