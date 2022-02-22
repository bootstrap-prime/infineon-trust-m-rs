#include "pal_os_timer.h"
#include "rustbindings.h"

uint32_t pal_os_timer_get_time_in_microseconds(void)
{
  return rust_hal_timer_get_time_us();
}

uint32_t pal_os_timer_get_time_in_milliseconds(void)
{
  return rust_hal_timer_get_time_ms();
}

void pal_os_timer_delay_in_milliseconds(uint16_t milliseconds)
{
  rust_hal_timer_delay_ms(milliseconds);
}

pal_status_t pal_timer_init(void)
{
  return PAL_STATUS_SUCCESS;
}

pal_status_t pal_timer_deinit(void)
{
  return PAL_STATUS_SUCCESS;
}
