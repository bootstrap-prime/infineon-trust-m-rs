#include "pal_i2c.h"
#include "optiga_lib_config.h"
#include "optiga_lib_logger.h"
#include "optiga_lib_return_codes.h"
#include "rustbindings.h"

LIBRARY_EXPORTS pal_status_t pal_i2c_init(const pal_i2c_t * p_i2c_context)
{
    return PAL_STATUS_SUCCESS;
}

LIBRARY_EXPORTS pal_status_t pal_i2c_set_bitrate(const pal_i2c_t * p_i2c_context, uint16_t bitrate)
{
    return PAL_STATUS_SUCCESS;
}

LIBRARY_EXPORTS pal_status_t pal_i2c_write(pal_i2c_t * p_i2c_context, uint8_t * p_data, uint16_t length)
{
  bool_t status = rust_hal_i2c_write(p_i2c_context->slave_address, p_data, length);
  if (status) {
    return PAL_STATUS_SUCCESS;
  } else {
    return PAL_STATUS_FAILURE;
  }
}

LIBRARY_EXPORTS pal_status_t pal_i2c_read(pal_i2c_t * p_i2c_context, uint8_t * p_data, uint16_t length)
{
  bool_t status = rust_hal_i2c_read(p_i2c_context->slave_address, p_data, length);
  if (status) {
    return PAL_STATUS_SUCCESS;
  } else {
    return PAL_STATUS_FAILURE;
  }
}

LIBRARY_EXPORTS pal_status_t pal_i2c_deinit(const pal_i2c_t * p_i2c_context)
{
	return PAL_STATUS_SUCCESS;
}
