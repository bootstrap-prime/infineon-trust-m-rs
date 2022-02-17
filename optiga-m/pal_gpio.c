#include "pal_gpio.h"
#include "rustbindings.h"

LIBRARY_EXPORTS void pal_gpio_set_high(const pal_gpio_t * p_gpio_context)
{
   if ((p_gpio_context != NULL) && (p_gpio_context->p_gpio_hw != NULL))
   {
     rust_hal_gpio_set_high(*(uint8_t*)p_gpio_context->p_gpio_hw);
   }
}

LIBRARY_EXPORTS void pal_gpio_set_low(const pal_gpio_t * p_gpio_context)
{
    if ((p_gpio_context != NULL) && (p_gpio_context->p_gpio_hw != NULL))
    {
      rust_hal_gpio_set_low(*(uint8_t*)p_gpio_context->p_gpio_hw);
    }
}

LIBRARY_EXPORTS pal_status_t pal_gpio_init(const pal_gpio_t * p_gpio_context)
{
    return PAL_STATUS_SUCCESS;
}

LIBRARY_EXPORTS pal_status_t pal_gpio_deinit(const pal_gpio_t * p_gpio_context)
{
    return PAL_STATUS_SUCCESS;
}
