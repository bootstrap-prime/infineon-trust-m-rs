#include "rustbindings.h"
#include "optiga/pal/pal.h"

#include "optiga/pal/pal_logger.h"
pal_logger_t logger_console =
{
    NULL,
    false,
    false,
};

#include "optiga/pal/pal_i2c.h"
#include "optiga/pal/pal_gpio.h"

pal_i2c_t optiga_pal_i2c_context_0 =
{
    /// Pointer to I2C master platform specific context
	NULL,
    /// Upper layer context
    NULL,
    /// Callback event handler
    NULL,
    /// Slave address
    0x30
};

pal_gpio_t optiga_vdd_0 =
{
    // Platform specific GPIO context for the pin used to toggle Vdd.
    NULL
};

pal_gpio_t optiga_reset_0 =
{
    // Platform specific GPIO context for the pin used to toggle Reset.
    NULL
};


pal_status_t pal_init(void)
{
    return PAL_STATUS_SUCCESS;
}

pal_status_t pal_deinit(void)
{
    return PAL_STATUS_SUCCESS;
}
