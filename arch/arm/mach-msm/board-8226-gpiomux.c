/* Copyright (c) 2012-2013, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/init.h>
#include <linux/ioport.h>
#include <mach/board.h>
#include <mach/gpio.h>
#include <mach/gpiomux.h>
#include <mach/socinfo.h>

#define KS8851_IRQ_GPIO 115

#if defined(CONFIG_MACH_MS01_CHN_CTC) || defined(CONFIG_MACH_CRATERVE_CHN_CTC)|| defined(CONFIG_MACH_MS01_EUR_3G) || \
	defined(CONFIG_MACH_CRATERQ)|| defined(CONFIG_MACH_MS01_CHN_CMCC_3G)  || defined(CONFIG_MACH_S3VE_CHN_OPEN) || defined(CONFIG_MACH_S3VE_CHN_CMCC) || \
	defined(CONFIG_MACH_HLITE_EUR_3GDS) || defined(CONFIG_MACH_BAFFIN2_CHN_CMCC)
#define NC_GPIO_CONFIG(gpio_num) { \
		.gpio = gpio_num, \
		.settings = { [GPIOMUX_ACTIVE] = &nc_suspend_cfg, }, \
		.settings = { [GPIOMUX_SUSPENDED] = &nc_suspend_cfg, } \
	}

static struct gpiomux_setting nc_suspend_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_IN,
};
#endif
#ifdef CONFIG_USB_EHCI_MSM_HSIC
static struct gpiomux_setting hsic_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_OUT_LOW,
};
static struct gpiomux_setting hsic_act_cfg = {
	.func = GPIOMUX_FUNC_1,
	.drv = GPIOMUX_DRV_16MA,
	.pull = GPIOMUX_PULL_NONE,
};

static struct msm_gpiomux_config msm_hsic_configs[] = {
	{
		.gpio = 115,               /* HSIC_STROBE */
		.settings = {
			[GPIOMUX_ACTIVE] = &hsic_act_cfg,
			[GPIOMUX_SUSPENDED] = &hsic_sus_cfg,
		},
	},
	{
		.gpio = 116,               /* HSIC_DATA */
		.settings = {
			[GPIOMUX_ACTIVE] = &hsic_act_cfg,
			[GPIOMUX_SUSPENDED] = &hsic_sus_cfg,
		},
	},
};
#endif

#if defined(CONFIG_MACH_CRATERQ)
#define GPIO_IN_NP_CONFIG(gpio_num) { \
		.gpio = gpio_num, \
		.settings = { [GPIOMUX_ACTIVE] = &gpio_in_np_cfg, }, \
		.settings = { [GPIOMUX_SUSPENDED] = &gpio_in_np_cfg, }, \
	}

static struct gpiomux_setting gpio_in_np_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_IN,
};
#endif

#if defined(CONFIG_KS8851) || defined(CONFIG_KS8851_MODULE)
static struct gpiomux_setting gpio_eth_config = {
	.pull = GPIOMUX_PULL_UP,
	.drv = GPIOMUX_DRV_2MA,
	.func = GPIOMUX_FUNC_GPIO,
};

static struct msm_gpiomux_config msm_eth_configs[] = {
	{
		.gpio = KS8851_IRQ_GPIO,
		.settings = {
			[GPIOMUX_SUSPENDED] = &gpio_eth_config,
		}
	},
};
#endif

#if defined(CONFIG_MACH_S3VE_CHN_OPEN) || defined(CONFIG_MACH_S3VE_CHN_CMCC) || defined(CONFIG_MACH_CRATERQ) || defined(CONFIG_MACH_HLITE_EUR_3GDS)
static struct gpiomux_setting uart_boot_on_gpio_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_IN,
};
#endif

#if defined(CONFIG_MACH_HLITE_EUR_3GDS)
static struct gpiomux_setting hw_chk_bit = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};

static struct msm_gpiomux_config hw_chk_bit_configs[] __initdata = {
	{
		.gpio = 62,
		.settings = {
			[GPIOMUX_ACTIVE] = &hw_chk_bit,
			[GPIOMUX_SUSPENDED] = &hw_chk_bit,
		},
	},
	{
		.gpio = 92,
		.settings = {
			[GPIOMUX_ACTIVE] = &hw_chk_bit,
			[GPIOMUX_SUSPENDED] = &hw_chk_bit,
		},
	},
};

static struct gpiomux_setting chg_pm8226_gpio_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_IN,
};
#endif

#if defined(CONFIG_KEYBOARD_CYPRESS_TOUCH_236)
#if defined(CONFIG_MACH_S3VE_CHN_OPEN) || defined(CONFIG_MACH_S3VE_CHN_CMCC)
static struct gpiomux_setting gpio_i2c_tkey_active_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};
static struct gpiomux_setting gpio_i2c_tkey_suspend_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
};
#endif
#endif

#if defined(CONFIG_TOUCHSCREEN_ZINITIX_BT531)
static struct gpiomux_setting zinitixs_gpio_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};
#elif defined(CONFIG_TOUCHSCREEN_ATMEL_MXTS)
static struct gpiomux_setting atmel_gpio_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};
#elif defined(CONFIG_TOUCHSCREEN_MMS144)
static struct gpiomux_setting melfas_gpio_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};
#elif defined(CONFIG_TOUCHSCREEN_SYNAPTICS_I2C_RMI4)
static struct gpiomux_setting synaptics_int_act_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting synaptics_int_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
};

static struct gpiomux_setting synaptics_reset_act_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_6MA,
	.pull = GPIOMUX_PULL_DOWN,
};

static struct gpiomux_setting synaptics_reset_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
};
#else
static struct gpiomux_setting tsp_default_gpio_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};
#endif

static struct gpiomux_setting gpio_keys_active = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting gpio_keys_suspend = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_UP,
};

#if defined(CONFIG_MACH_CS03_SGLTE)
static struct gpiomux_setting gpio_home_keys_active = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting gpio_home_keys_suspend = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_UP,
};
#else
static struct gpiomux_setting gpio_home_keys_active = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};

static struct gpiomux_setting gpio_home_keys_suspend = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};
#endif

#if defined (CONFIG_MACH_CRATERQ)
static struct gpiomux_setting lcd_rst_act_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_UP,
	.dir = GPIOMUX_OUT_HIGH,
};

static struct gpiomux_setting lcd_rst_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_OUT_LOW,
};

static struct msm_gpiomux_config msm_lcd_nowrite_configs[] __initdata = {
	{
		.gpio = 25,
		.settings = {
			[GPIOMUX_ACTIVE]    = &lcd_rst_act_cfg,
			[GPIOMUX_SUSPENDED] = &lcd_rst_sus_cfg,
		},
	},
};

#if 0
static struct gpiomux_setting lcd_det_act_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting lcd_det_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_IN,
};

static struct msm_gpiomux_config msm_lcd_write_configs[] __initdata = {
	{	/* LCD DET GPIO */
		.gpio = 16,
		.settings = {
			[GPIOMUX_ACTIVE]    = &lcd_det_act_cfg,
			[GPIOMUX_SUSPENDED] = &lcd_det_sus_cfg,
		},
	},
};
#endif
#endif

#if !defined(CONFIG_MACH_MILLET3G_EUR)

static struct gpiomux_setting gpio_spi_act_config = {
	.func = GPIOMUX_FUNC_1,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_DOWN,
};

static struct gpiomux_setting gpio_spi_cs_act_config = {
	.func = GPIOMUX_FUNC_1,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_DOWN,
};
static struct gpiomux_setting gpio_spi_susp_config = {

	.func = GPIOMUX_FUNC_1,
	.drv = GPIOMUX_DRV_6MA,
	.pull = GPIOMUX_PULL_DOWN,
};
#endif
static struct gpiomux_setting wcnss_5wire_suspend_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv  = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting wcnss_5wire_active_cfg = {
	.func = GPIOMUX_FUNC_1,
	.drv  = GPIOMUX_DRV_6MA,
	.pull = GPIOMUX_PULL_DOWN,
};

static struct gpiomux_setting gpio_i2c_config = {
	.func = GPIOMUX_FUNC_3,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};

#if defined(CONFIG_TOUCHSCREEN_ZINITIX_BT531)
static struct gpiomux_setting gpio_i2c_tsp_active_config = {
	.func = GPIOMUX_FUNC_3,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_UP,
};
static struct gpiomux_setting gpio_i2c_tsp_suspend_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};

#elif defined(CONFIG_TOUCHSCREEN_ATMEL_MXTS)
static struct gpiomux_setting gpio_i2c_tsp_active_config = {
	.func = GPIOMUX_FUNC_3,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};
static struct gpiomux_setting gpio_i2c_tsp_suspend_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};
#elif defined(CONFIG_TOUCHSCREEN_MMS144)
static struct gpiomux_setting gpio_i2c_tsp_active_config = {
	.func = GPIOMUX_FUNC_3,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};
static struct gpiomux_setting gpio_i2c_tsp_suspend_config = {
	.func = GPIOMUX_FUNC_3,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};
#elif defined(CONFIG_MACH_CRATERQ)
static struct gpiomux_setting gpio_i2c_tsp_active_config = {
	.func = GPIOMUX_FUNC_3,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};
static struct gpiomux_setting gpio_i2c_tsp_suspend_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};
#elif defined(CONFIG_MACH_CRATERVE)
static struct gpiomux_setting gpio_i2c_tsp_active_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};
static struct gpiomux_setting gpio_i2c_tsp_suspend_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};

#else
static struct gpiomux_setting gpio_i2c_tsp_active_config = {
	.func = GPIOMUX_FUNC_3,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_UP,
};
static struct gpiomux_setting gpio_i2c_tsp_suspend_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
};
#endif

#if defined(CONFIG_YAS_ACC_DRIVER_BMA250) || defined(CONFIG_INPUT_MPU6500) || \
defined(CONFIG_PROXIMITY_SENSOR) || defined (CONFIG_SENSORS_HSCDTD008A) || \
defined(CONFIG_SENSORS_INVENSENSE) || defined(CONFIG_SENSORS_TMD27723) || \
defined(CONFIG_SENSORS_AK09911C)
static struct gpiomux_setting sensor_gpio_i2c_config = {
	.func = GPIOMUX_FUNC_3,
	.drv = GPIOMUX_DRV_2MA,
#if defined(CONFIG_MACH_CRATERQ)|| defined(CONFIG_MACH_CRATERVE_CHN_CTC) || defined(CONFIG_MACH_HLITE_EUR_3GDS)
	.pull = GPIOMUX_PULL_NONE,
#else
	.pull = GPIOMUX_PULL_DOWN,
#endif	
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting accel_irq_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
#if defined(CONFIG_MACH_CRATERQ)|| defined(CONFIG_MACH_CRATERVE_CHN_CTC)
	.pull = GPIOMUX_PULL_NONE,
#else
	.pull = GPIOMUX_PULL_DOWN,
#endif
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting prox_irq_config = {
    .func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
#if defined(CONFIG_MACH_CRATERQ) || defined(CONFIG_MACH_CRATERVE_CHN_CTC) || defined(CONFIG_MACH_S3VE_CHN_CTC) || defined(CONFIG_MACH_S3VE) || defined(CONFIG_MACH_HLITE_EUR_3GDS)
	.pull = GPIOMUX_PULL_NONE,
#else
	.pull = GPIOMUX_PULL_DOWN,
#endif	
	.dir = GPIOMUX_IN,
};

#if !defined(CONFIG_MACH_S3VE_CHN_OPEN) && !defined(CONFIG_MACH_S3VE_CHN_CMCC) && !defined(CONFIG_MACH_HLITE_EUR_3GDS)
static struct gpiomux_setting mag_irq_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_IN,
};
#if !defined(CONFIG_MACH_MS01_CHN_CTC) && !defined(CONFIG_MACH_CRATERVE_CHN_CTC) && !defined(CONFIG_MACH_CRATERQ)
static struct gpiomux_setting prox_en_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting prox_en_suspend_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_IN,
};
#endif
#endif
#if defined(CONFIG_MACH_HLITE_EUR_3GDS)
static struct gpiomux_setting mag_rstn_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_OUT_HIGH,
};
#endif
#endif

#if defined(CONFIG_SEC_NFC_I2C) || defined(CONFIG_NFC_PN547)
static struct gpiomux_setting nfc_gpio_i2c_config = {
	.func = GPIOMUX_FUNC_3,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting nfc_ven_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_OUT_LOW,
};

static struct gpiomux_setting nfc_tx_en_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_OUT_LOW,
};

static struct gpiomux_setting nfc_irq_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting nfc_firmware_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_OUT_LOW,
};
#elif defined(CONFIG_BCM2079X_NFC_I2C)
static struct gpiomux_setting nfc_irq_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting nfc_firmware_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_OUT_LOW,
};
#else
static struct gpiomux_setting nc_tx_en_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_IN,
};
#if !defined(CONFIG_MACH_BAFFIN2_CHN_CMCC)
static struct gpiomux_setting nc_irq_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_IN,
};
#endif
#endif

#if defined(CONFIG_MACH_MS01_EUR_3G) || defined(CONFIG_MACH_MS01_LTE) || defined(CONFIG_MACH_MILLET3G_EUR) || defined(CONFIG_MACH_MS01_CHN_CTC) \
    || defined(CONFIG_MACH_MS01_LTE_KOR) || defined(CONFIG_MACH_CRATERVE_CHN_CTC) || defined(CONFIG_MACH_S3VE)|| defined(CONFIG_MACH_MS01_CHN_CMCC_3G) \
    || defined(CONFIG_MACH_HLITE_EUR_3GDS)
static struct gpiomux_setting hall_active_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
#if defined(CONFIG_MACH_S3VE) || defined(CONFIG_MACH_HLITE_EUR_3GDS)
	.pull = GPIOMUX_PULL_UP,
#else
	.pull = GPIOMUX_PULL_NONE,
#endif
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting hall_suspend_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
#if defined(CONFIG_MACH_S3VE) || defined(CONFIG_MACH_HLITE_EUR_3GDS)
	.pull = GPIOMUX_PULL_UP,
#else
	.pull = GPIOMUX_PULL_NONE,
#endif
	.dir = GPIOMUX_IN,
};

static struct msm_gpiomux_config msm_hall_configs[] __initdata = {
	{
		.gpio = 50,
		.settings = {
			[GPIOMUX_ACTIVE]    = &hall_active_cfg,
			[GPIOMUX_SUSPENDED] = &hall_suspend_cfg,
		},
	},
};
#endif

static struct msm_gpiomux_config msm_keypad_configs[] __initdata = {
	{
		.gpio = 106,
		.settings = {
			[GPIOMUX_ACTIVE]    = &gpio_keys_active,
			[GPIOMUX_SUSPENDED] = &gpio_keys_suspend,
		},
	},
	{
		.gpio = 107,
		.settings = {
			[GPIOMUX_ACTIVE]    = &gpio_keys_active,
			[GPIOMUX_SUSPENDED] = &gpio_keys_suspend,
		},
	},
	{
		.gpio = 108,
		.settings = {
			[GPIOMUX_ACTIVE]    = &gpio_home_keys_active,
			[GPIOMUX_SUSPENDED] = &gpio_home_keys_suspend,
		},
	},
};

#if defined(CONFIG_FB_MSM_MDSS_SHARP_HD_PANEL)\
	|| defined(CONFIG_MACH_MILLET3G_EUR)

static struct gpiomux_setting lcd_rst_act_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_UP,
	.dir = GPIOMUX_OUT_HIGH,
};

static struct gpiomux_setting lcd_rst_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_OUT_LOW,
};

static struct gpiomux_setting lcd_power_act_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_OUT_HIGH,
};

static struct gpiomux_setting lcd_power_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_OUT_LOW,
};
#endif
#if defined(CONFIG_MACH_MS01_EUR_3G) || defined(CONFIG_MACH_MS01_LTE) || defined(CONFIG_MACH_CRATERQ) || defined(CONFIG_MACH_MS01_CHN_CTC) \
    || defined(CONFIG_MACH_MS01_LTE_KOR) || defined(CONFIG_MACH_CRATERVE_CHN_CTC) || defined(CONFIG_MACH_S3VE_CHN_OPEN) || defined(CONFIG_MACH_S3VE_CHN_CMCC) || defined(CONFIG_MACH_MS01_CHN_CMCC_3G) \
    || defined(CONFIG_MACH_HLITE_EUR_3GDS)
static struct gpiomux_setting muic_i2c_act_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
        .drv = GPIOMUX_DRV_2MA,
        .pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting muic_i2c_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
        .drv = GPIOMUX_DRV_2MA,
        .pull = GPIOMUX_PULL_NONE,
        .dir = GPIOMUX_IN,
};

static struct msm_gpiomux_config muic_i2c_configs[] = {
	{
		.gpio = 4,
		.settings = {
			[GPIOMUX_ACTIVE] = &muic_i2c_act_cfg,
			[GPIOMUX_SUSPENDED] = &muic_i2c_sus_cfg,
		},
	},
};
#endif
#if defined(CONFIG_FB_MSM_MDSS_SHARP_HD_PANEL)
static struct msm_gpiomux_config msm_lcd_configs[] __initdata = {
	{
		.gpio = 25,
		.settings = {
			[GPIOMUX_ACTIVE]    = &lcd_rst_act_cfg,
			[GPIOMUX_SUSPENDED] = &lcd_rst_sus_cfg,
		},
	},
	{
		.gpio = 56,
		.settings = {
			[GPIOMUX_ACTIVE]    = &lcd_power_act_cfg,
			[GPIOMUX_SUSPENDED] = &lcd_power_sus_cfg,
		},
	},
	{
		.gpio = 60,
		.settings = {
			[GPIOMUX_ACTIVE]    = &lcd_power_act_cfg,
			[GPIOMUX_SUSPENDED] = &lcd_power_sus_cfg,
		},
	},
#if !defined(CONFIG_MACH_HLITE_EUR_3GDS)	
	{
		.gpio = 63,
		.settings = {
			[GPIOMUX_ACTIVE]    = &lcd_power_act_cfg,
			[GPIOMUX_SUSPENDED] = &lcd_power_sus_cfg,
		},
	}
#endif
};
#elif defined(CONFIG_MACH_MILLET3G_EUR)
static struct msm_gpiomux_config msm_lcd_configs[] __initdata = {
	{
		.gpio = 25,
		.settings = {
			[GPIOMUX_ACTIVE]    = &lcd_rst_act_cfg,
			[GPIOMUX_SUSPENDED] = &lcd_rst_sus_cfg,
		},
	},
	{
		.gpio = 53,
		.settings = {
			[GPIOMUX_ACTIVE]    = &lcd_power_act_cfg,
			[GPIOMUX_SUSPENDED] = &lcd_power_sus_cfg,
		},
	},
	{
		.gpio = 74,
		.settings = {
			[GPIOMUX_ACTIVE]    = &lcd_power_act_cfg,
			[GPIOMUX_SUSPENDED] = &lcd_power_sus_cfg,
		},
	},
	{
		.gpio = 21,
		.settings = {
			[GPIOMUX_ACTIVE]    = &lcd_power_act_cfg,
			[GPIOMUX_SUSPENDED] = &lcd_power_sus_cfg,
		},
	},
	{
		.gpio = 20,
		.settings = {
			[GPIOMUX_ACTIVE]    = &lcd_power_act_cfg,
			[GPIOMUX_SUSPENDED] = &lcd_power_sus_cfg,
		},
	},
	{
		.gpio = 22,
		.settings = {
			[GPIOMUX_ACTIVE]    = &lcd_power_act_cfg,
			[GPIOMUX_SUSPENDED] = &lcd_power_sus_cfg,
		},
	}
};
#endif

static struct gpiomux_setting gpio_uart_rx_sleep_config = {
	.func = GPIOMUX_FUNC_2,
	.drv = GPIOMUX_DRV_16MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_OUT_HIGH,
};

static struct gpiomux_setting gpio_uart_sleep_config = {
	.func = GPIOMUX_FUNC_2,
	.drv = GPIOMUX_DRV_16MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_OUT_HIGH,
};

#if defined(CONFIG_MACH_BAFFIN2_CHN_CMCC)
static struct gpiomux_setting gpio_uart_sleep_config1 = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
};

static struct gpiomux_setting gpio_uart_active_config1 = {
	.func = GPIOMUX_FUNC_2,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_NONE,
};
#endif

static struct msm_gpiomux_config msm_blsp_configs[] __initdata = {
#if !defined(CONFIG_MACH_MILLET3G_EUR)
	{
		.gpio      = 0,		/* BLSP1 QUP1 SPI_DATA_MOSI */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_spi_act_config,
			[GPIOMUX_SUSPENDED] = &gpio_spi_susp_config,
		},
	},
	{
		.gpio      = 1,		/* BLSP1 QUP1 SPI_DATA_MISO */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_spi_act_config,
			[GPIOMUX_SUSPENDED] = &gpio_spi_susp_config,
		},
	},
	{
		.gpio      = 2,		/* BLSP1 QUP1 SPI_CS1 */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_spi_cs_act_config,
			[GPIOMUX_SUSPENDED] = &gpio_spi_susp_config,
		},
	},
	{
		.gpio      = 3,		/* BLSP1 QUP1 SPI_CLK */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_spi_act_config,
			[GPIOMUX_SUSPENDED] = &gpio_spi_susp_config,
		},
	},
#else
	{
		.gpio      = 2,		/* BLSP1 QUP1 I2C_SDA */
		.settings = {
			[GPIOMUX_SUSPENDED] = &gpio_i2c_config,
		},
	},
	{
		.gpio      = 3,		/* BLSP1 QUP1 I2C_SCL */
		.settings = {
			[GPIOMUX_SUSPENDED] = &gpio_i2c_config,
		},
	},
#endif	
	{
		.gpio      = 8,	/* BLSP1 UART2 TX */
		.settings = {
			[GPIOMUX_SUSPENDED] = &gpio_uart_sleep_config,
		},
	},
	{
		.gpio      = 9,	/* BLSP1 UART2 RX */
		.settings = {
			[GPIOMUX_SUSPENDED] = &gpio_uart_rx_sleep_config,
		},
	},
#if 0 /*Need to enable these gpios for the 4 PIN UART system*/
	{
		.gpio      = 6,	/* BLSP1 UART2 CTS */
		.settings = {
			[GPIOMUX_SUSPENDED] = &gpio_i2c_config,
		},
	},
	{
		.gpio      = 7,	/* BLSP1 QUART2 RFR */
		.settings = {
			[GPIOMUX_SUSPENDED] = &gpio_i2c_config,
		},
	}
#endif
#if !defined(CONFIG_MACH_CRATERQ) && !defined(CONFIG_MACH_BAFFIN2_CHN_CMCC)
	{
		.gpio      = 14,	/* BLSP1 QUP4 I2C_SDA */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_i2c_config,
			[GPIOMUX_SUSPENDED] = &gpio_i2c_config,
		},
	},
	{
		.gpio      = 15,	/* BLSP1 QUP4 I2C_SCL */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_i2c_config,
			[GPIOMUX_SUSPENDED] = &gpio_i2c_config,
		},
	},
#endif
	{
		.gpio      = 18,		/* BLSP1 QUP5 I2C_SDA */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_i2c_tsp_active_config,
			[GPIOMUX_SUSPENDED] = &gpio_i2c_tsp_suspend_config,
		},
	},
	{
		.gpio      = 19,		/* BLSP1 QUP5 I2C_SCL */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_i2c_tsp_active_config,
			[GPIOMUX_SUSPENDED] = &gpio_i2c_tsp_suspend_config,
		},
	},
#if defined (CONFIG_MACH_BAFFIN2_CHN_CMCC)
	{
		.gpio      = 20,	/* BLSP6 UART5 TX */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_uart_active_config1,
			[GPIOMUX_SUSPENDED] = &gpio_uart_sleep_config1,
		},
	},
	{
		.gpio      = 21,	/* BLSP6 UART5 RX */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_uart_active_config1,
			[GPIOMUX_SUSPENDED] = &gpio_uart_sleep_config1,
		},
	},
	{
		.gpio      = 22,	/* BLSP6 UART5 CTS */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_uart_active_config1,
			[GPIOMUX_SUSPENDED] = &gpio_uart_sleep_config1,
		},
	},
	{
		.gpio      = 23,	/* BLSP6 UART5 RFR */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_uart_active_config1,
			[GPIOMUX_SUSPENDED] = &gpio_uart_sleep_config1,
		},
	},
#else
#if !defined(CONFIG_MACH_MILLET3G_EUR) && !defined(CONFIG_MACH_CS03_SGLTE) && !defined(CONFIG_MACH_CRATERQ)&& !defined(CONFIG_MACH_CRATERVE_CHN_CTC) && !defined(CONFIG_MACH_HLITE_EUR_3GDS)
	{
		.gpio      = 22,		/* BLSP1 QUP6 SPI_CS_ETH */
		.settings = {
			[GPIOMUX_SUSPENDED] = &gpio_i2c_config,
		},
	},
#endif
#if !defined(CONFIG_MACH_MILLET3G_EUR) && !defined(CONFIG_MACH_S3VE_CHN_OPEN) &&!defined(CONFIG_MACH_S3VE_CHN_CMCC) && !defined(CONFIG_MACH_S3VE_CHN_CTC) && !defined(CONFIG_MACH_CS03_SGLTE) && !defined(CONFIG_MACH_HLITE_EUR_3GDS)
	{
		.gpio      = 23,		/* BLSP1 QUP6 SPI_CS_ETH */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_i2c_config,
			[GPIOMUX_SUSPENDED] = &gpio_i2c_config,
		},
	},
#endif
#endif
#if defined(CONFIG_SEC_NFC_I2C) || defined(CONFIG_NFC_PN547)
#if !defined(CONFIG_MACH_CT01_CHN_CU) && !defined(CONFIG_MACH_HLITE_EUR_3GDS)
	{					/*  NFC   */
		.gpio      = 10,		/* BLSP1 QUP3 I2C_DAT */
		.settings = {
			[GPIOMUX_SUSPENDED] = &nfc_gpio_i2c_config,
		},
	},
	{					/*  NFC   */
		.gpio      = 11,		/* BLSP1 QUP3 I2C_CLK */
		.settings = {
			[GPIOMUX_SUSPENDED] = &nfc_gpio_i2c_config,
		},
	},
#endif
#elif defined(CONFIG_BCM2079X_NFC_I2C)
	{					/*	NFC   */
		.gpio	   = 10,		/* BLSP1 QUP3 I2C_DAT */
		.settings = {
			[GPIOMUX_SUSPENDED] = &gpio_i2c_config,
		},
	},
	{					/*	NFC   */
		.gpio	   = 11,		/* BLSP1 QUP3 I2C_CLK */
		.settings = {
			[GPIOMUX_SUSPENDED] = &gpio_i2c_config,
		},
	},
#endif
#if defined(CONFIG_MACH_CT01_CHN_CU)
	{					/*  Grip Sensor   */
		.gpio      = 10,		/* BLSP1 QUP3 I2C_DAT */
		.settings = {
			[GPIOMUX_SUSPENDED] = &sensor_gpio_i2c_config,
		},
	},
	{					/*  Grip Sensor   */
		.gpio      = 11,		/* BLSP1 QUP3 I2C_CLK */
		.settings = {
			[GPIOMUX_SUSPENDED] = &sensor_gpio_i2c_config,
		},
	},
#endif

#if defined(CONFIG_YAS_ACC_DRIVER_BMA250) || defined(CONFIG_INPUT_MPU6500) || \
defined(CONFIG_PROXIMITY_SENSOR) || defined (CONFIG_SENSORS_HSCDTD008A) || \
defined(CONFIG_SENSORS_INVENSENSE) || defined(CONFIG_SENSORS_TMD27723) || \
defined(CONFIG_SENSORS_AK09911C)
    {
		.gpio      = 6,		/* BLSP1 QUP2 I2C_SDA */
		.settings = {
			[GPIOMUX_SUSPENDED] = &sensor_gpio_i2c_config,
		},
	},
	{
		.gpio      = 7,		/* BLSP1 QUP2 I2C_SCL */
		.settings = {
			[GPIOMUX_SUSPENDED] = &sensor_gpio_i2c_config,
		},
	},
#endif

#if defined(CONFIG_KEYBOARD_CYPRESS_TOUCH_236)
#if defined(CONFIG_MACH_S3VE_CHN_OPEN) || defined(CONFIG_MACH_S3VE_CHN_CMCC)
	{
		.gpio      = 49,		/* 2_TOUCH_INT */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_i2c_tkey_active_config,
			[GPIOMUX_SUSPENDED] = &gpio_i2c_tkey_suspend_config,
		},
	},
	{
		.gpio      = 66,		/* 2_TOUCH_I2C_SCL */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_i2c_tkey_active_config,
			[GPIOMUX_SUSPENDED] = &gpio_i2c_tkey_suspend_config,
		},
	},
	{
		.gpio      = 114,		/* 2_TOUCH_I2C_SDA */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_i2c_tkey_active_config,
			[GPIOMUX_SUSPENDED] = &gpio_i2c_tkey_suspend_config,
		},
	},
#endif
#endif
#if defined(CONFIG_MACH_S3VE_CHN_OPEN) || defined(CONFIG_MACH_CRATERVE_CHN_CTC) || defined(CONFIG_MACH_S3VE_CHN_CMCC) || defined(CONFIG_MACH_CRATERQ) || defined(CONFIG_MACH_HLITE_EUR_3GDS)
	{
		.gpio	   = 109,		/* UART boot on gpio */
		.settings = {
			[GPIOMUX_ACTIVE] = &uart_boot_on_gpio_config,
			[GPIOMUX_SUSPENDED] = &uart_boot_on_gpio_config,
		},
	},
#endif	
};

#if defined(CONFIG_TOUCHSCREEN_ZINITIX_BT531)
static struct msm_gpiomux_config msm_zinitixs_configs[] __initdata = {
	{
		.gpio = 17,
		.settings = {
			[GPIOMUX_SUSPENDED] = &zinitixs_gpio_sus_cfg,
		},
	},
};

#elif defined(CONFIG_TOUCHSCREEN_ATMEL_MXTS)
static struct msm_gpiomux_config msm_atmel_configs[] __initdata = {
	{
		.gpio = 17,
		.settings = {
			[GPIOMUX_ACTIVE] = &atmel_gpio_sus_cfg,
			[GPIOMUX_SUSPENDED] = &atmel_gpio_sus_cfg,
		},
	},
};
#elif defined(CONFIG_TOUCHSCREEN_MMS144)
static struct msm_gpiomux_config msm_melfas_configs[] __initdata = {
	{
		.gpio = 17,
		.settings = {
			[GPIOMUX_ACTIVE] = &melfas_gpio_sus_cfg,
			[GPIOMUX_SUSPENDED] = &melfas_gpio_sus_cfg,
		},
	},
};
#elif defined(CONFIG_TOUCHSCREEN_SYNAPTICS_I2C_RMI4)
static struct msm_gpiomux_config msm_synaptics_configs[] __initdata = {
	{
		.gpio = 16,
		.settings = {
			[GPIOMUX_ACTIVE] = &synaptics_reset_act_cfg,
			[GPIOMUX_SUSPENDED] = &synaptics_reset_sus_cfg,
		},
	},
	{
		.gpio = 17,
		.settings = {
			[GPIOMUX_ACTIVE] = &synaptics_int_act_cfg,
			[GPIOMUX_SUSPENDED] = &synaptics_int_sus_cfg,
		},
	},
};
#else
static struct msm_gpiomux_config msm_tsp_default_configs[] __initdata = {
	{
		.gpio = 17,
		.settings = {
			[GPIOMUX_ACTIVE] = &tsp_default_gpio_sus_cfg,
			[GPIOMUX_SUSPENDED] = &tsp_default_gpio_sus_cfg,
		},
	},
};

#endif

#if defined(CONFIG_MACH_HLITE_EUR_3GDS)
static struct msm_gpiomux_config chg_pm8226_configs[] __initdata = {
	{
		.gpio = 51,
		.settings = {
			[GPIOMUX_ACTIVE] = &chg_pm8226_gpio_cfg,
			[GPIOMUX_SUSPENDED] = &chg_pm8226_gpio_cfg,
		},
	},
};
#endif

static struct gpiomux_setting gpio_nc_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};

static struct gpiomux_setting goodix_ldo_en_act_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_6MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting goodix_ldo_en_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_6MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting goodix_int_act_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting goodix_int_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
};

static struct gpiomux_setting goodix_reset_act_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting goodix_reset_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct msm_gpiomux_config msm_qrd_blsp_configs[] __initdata = {
	{
		.gpio      = 2,		/* NC */
		.settings = {
			[GPIOMUX_SUSPENDED] = &gpio_nc_cfg,
		},
	},
	{
		.gpio      = 3,		/* NC */
		.settings = {
			[GPIOMUX_SUSPENDED] = &gpio_nc_cfg,
		},
	},
	{
		.gpio      = 4,		/* NC */
		.settings = {
			[GPIOMUX_SUSPENDED] = &gpio_nc_cfg,
		},
	},
	{
		.gpio      = 14,	/* NC */
		.settings = {
			[GPIOMUX_SUSPENDED] = &gpio_nc_cfg,
		},
	},
};

static struct msm_gpiomux_config msm_qrd_goodix_configs[] __initdata = {
	{
		.gpio = 15,		/* LDO EN */
		.settings = {
			[GPIOMUX_ACTIVE] = &goodix_ldo_en_act_cfg,
			[GPIOMUX_SUSPENDED] = &goodix_ldo_en_sus_cfg,
		},
	},
	{
		.gpio = 16,		/* RESET */
		.settings = {
			[GPIOMUX_ACTIVE] = &goodix_reset_act_cfg,
			[GPIOMUX_SUSPENDED] = &goodix_reset_sus_cfg,
		},
	},
	{
		.gpio = 17,		/* INT */
		.settings = {
			[GPIOMUX_ACTIVE] = &goodix_int_act_cfg,
			[GPIOMUX_SUSPENDED] = &goodix_int_sus_cfg,
		},
	},
	{
		.gpio      = 18,		/* BLSP1 QUP5 I2C_SDA */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_i2c_config,
			[GPIOMUX_SUSPENDED] = &gpio_i2c_config,
		},
	},
	{
		.gpio      = 19,		/* BLSP1 QUP5 I2C_SCL */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_i2c_config,
			[GPIOMUX_SUSPENDED] = &gpio_i2c_config,
		},
	},
};

static struct gpiomux_setting nfc_ldo_act_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_6MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting nfc_ldo_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_6MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting nfc_regc_act_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_6MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting nfc_regc_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_OUT_LOW,
};

static struct gpiomux_setting nfc_wake_act_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_6MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting nfc_wake_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_OUT_LOW,
};

static struct msm_gpiomux_config msm_skuf_nfc_configs[] __initdata = {
	{					/*  NFC  LDO EN */
		.gpio      = 0,
		.settings = {
			[GPIOMUX_ACTIVE] = &nfc_ldo_act_cfg,
			[GPIOMUX_SUSPENDED] = &nfc_ldo_sus_cfg,
		},
	},
	{					/*  NFC  REGC*/
		.gpio      = 1,
		.settings = {
			[GPIOMUX_ACTIVE] = &nfc_regc_act_cfg,
			[GPIOMUX_SUSPENDED] = &nfc_regc_sus_cfg,
		},
	},
	{					/*  NFC   WAKE */
		.gpio      = 5,
		.settings = {
			[GPIOMUX_ACTIVE] = &nfc_wake_act_cfg,
			[GPIOMUX_SUSPENDED] = &nfc_wake_sus_cfg,
		},
	},
#if !defined(CONFIG_BCM2079X_NFC_I2C)
	{					/*  NFC   */
		.gpio      = 10,		/* BLSP1 QUP3 I2C_DAT */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_i2c_config,
			[GPIOMUX_SUSPENDED] = &gpio_i2c_config,
		},
	},
	{					/*  NFC   */
		.gpio      = 11,		/* BLSP1 QUP3 I2C_CLK */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_i2c_config,
			[GPIOMUX_SUSPENDED] = &gpio_i2c_config,
		},
	},
#endif
};

static struct gpiomux_setting sd_card_det_active_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting sd_card_det_sleep_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_IN,
};

static struct msm_gpiomux_config sd_card_det __initdata = {
	.gpio = 38,
	.settings = {
		[GPIOMUX_ACTIVE]    = &sd_card_det_active_config,
		[GPIOMUX_SUSPENDED] = &sd_card_det_sleep_config,
	},
};

#if defined(CONFIG_MACH_BAFFIN2_CHN_CMCC)
static struct msm_gpiomux_config baffin2_cmcc_sd_card_det __initdata = {
	.gpio = 110,
	.settings = {
		[GPIOMUX_ACTIVE]    = &sd_card_det_active_config,
		[GPIOMUX_SUSPENDED] = &sd_card_det_sleep_config,
	},
};

static struct msm_gpiomux_config baffin2_cmcc_sd_card_det_rev06 __initdata = {
	.gpio = 62,
	.settings = {
		[GPIOMUX_ACTIVE]    = &sd_card_det_active_config,
		[GPIOMUX_SUSPENDED] = &sd_card_det_sleep_config,
	},
};

#endif

#if defined(CONFIG_YAS_ACC_DRIVER_BMA250) || defined(CONFIG_INPUT_MPU6500) || \
defined(CONFIG_PROXIMITY_SENSOR) || defined (CONFIG_SENSORS_HSCDTD008A) || \
defined(CONFIG_SENSORS_INVENSENSE) || defined(CONFIG_SENSORS_TMD27723) || \
defined(CONFIG_SENSORS_AK09911C)
static struct msm_gpiomux_config msm_sensors_configs[] __initdata = {
#if defined(CONFIG_MACH_CT01_CHN_CU)
	{
		.gpio		= 62,		/* GRIP IRQ */
		.settings = {
			[GPIOMUX_ACTIVE] = &prox_irq_config,
			[GPIOMUX_SUSPENDED] = &prox_irq_config,
		},
	},
#endif
#if defined(CONFIG_MACH_HLITE_EUR_3GDS)
	{
		.gpio      = 64,		/* PROXY IRQ */
		.settings = {
			[GPIOMUX_ACTIVE] = &prox_irq_config,
			[GPIOMUX_SUSPENDED] = &prox_irq_config,
		},
	},
#else
	{
		.gpio      = 65,		/* PROXY IRQ */
		.settings = {
			[GPIOMUX_ACTIVE] = &prox_irq_config,
			[GPIOMUX_SUSPENDED] = &prox_irq_config,
		},
	},
#endif
#if defined(CONFIG_MACH_CS03_SGLTE)	
	{
  		.gpio	   = 67,		/* ACCEL IRQ */
  		.settings = {
  			[GPIOMUX_ACTIVE] = &accel_irq_config,
  			[GPIOMUX_SUSPENDED] = &accel_irq_config,
  		},
	},
#elif defined(CONFIG_MACH_HLITE_EUR_3GDS)
	{
		.gpio	   = 63,		/* ACCEL IRQ */
		.settings = {
			[GPIOMUX_ACTIVE] = &accel_irq_config,
			[GPIOMUX_SUSPENDED] = &accel_irq_config,
		},
	},
#else
	{
		.gpio      = 64,		/* ACCEL IRQ */
		.settings = {
			[GPIOMUX_ACTIVE] = &accel_irq_config,
			[GPIOMUX_SUSPENDED] = &accel_irq_config,
		},
	},
#endif	
#if !defined(CONFIG_MACH_S3VE_CHN_OPEN) && !defined(CONFIG_MACH_S3VE_CHN_CMCC) && !defined(CONFIG_MACH_HLITE_EUR_3GDS)
	{
		.gpio      = 66,		/* MAG IRQ */
		.settings = {
			[GPIOMUX_ACTIVE] = &mag_irq_config,
			[GPIOMUX_SUSPENDED] = &mag_irq_config,
		},
	},
#if !defined(CONFIG_MACH_MS01_CHN_CTC) && !defined(CONFIG_MACH_CRATERVE_CHN_CTC) && !defined(CONFIG_MACH_CRATERQ)
	{
		.gpio      = 49,		/* PROXY ENABLE */
		.settings = {
			[GPIOMUX_ACTIVE] = &prox_en_config,
			[GPIOMUX_SUSPENDED] = &prox_en_suspend_config,
		},
	},
#endif
#endif
#if defined(CONFIG_MACH_HLITE_EUR_3GDS)
	{
		.gpio      = 65,		/* MAG IRQ */
		.settings = {
			[GPIOMUX_ACTIVE] = &mag_rstn_config,
			[GPIOMUX_SUSPENDED] = &mag_rstn_config,
		},
	},
#endif
};
#endif
#if defined(CONFIG_SEC_NFC_I2C) || defined(CONFIG_NFC_PN547)
static struct msm_gpiomux_config msm_nfc_configs[] __initdata = {
	{
		.gpio      = 21,		/* NFC IRQ */
		.settings = {
			[GPIOMUX_ACTIVE] = &nfc_irq_cfg,
			[GPIOMUX_SUSPENDED] = &nfc_irq_cfg,
		},
	},
#if !defined(CONFIG_MACH_CT01_CHN_CU)
	{
		.gpio		= 62,		/* NFC FIRMWARE */
		.settings = {
			[GPIOMUX_ACTIVE] = &nfc_firmware_cfg,
			[GPIOMUX_SUSPENDED] = &nfc_firmware_cfg,
		},
	},
#endif
	{
		.gpio		= 36,		/* NFC TX EN*/
		.settings = {
			[GPIOMUX_ACTIVE] = &nfc_tx_en_cfg,
			[GPIOMUX_SUSPENDED] = &nfc_tx_en_cfg,
		},
	},
	{
		.gpio		= 20,		/* NFC VEN */
		.settings = {
			[GPIOMUX_ACTIVE] = &nfc_ven_cfg,
			[GPIOMUX_SUSPENDED] = &nfc_ven_cfg,
		},
	},
};
#elif defined(CONFIG_BCM2079X_NFC_I2C)
static struct msm_gpiomux_config msm_nfc_configs[] __initdata = {
#if !defined(CONFIG_MACH_BAFFIN2_CHN_CMCC)
	{
		.gpio      = 21,		/* NFC IRQ */
		.settings = {
			[GPIOMUX_ACTIVE] = &nfc_irq_cfg,
			[GPIOMUX_SUSPENDED] = &nfc_irq_cfg,
		},
	},
#endif
	{
		.gpio		= 62,		/* NFC FIRMWARE */
		.settings = {
			[GPIOMUX_ACTIVE] = &nfc_firmware_cfg,
			[GPIOMUX_SUSPENDED] = &nfc_firmware_cfg,
		},
	},
};
#else
static struct msm_gpiomux_config msm_nc_configs[] __initdata = {
#if !defined(CONFIG_MACH_BAFFIN2_CHN_CMCC)
	{
		.gpio      = 21,		/* NFC IRQ */
		.settings = {
			[GPIOMUX_ACTIVE] = &nc_irq_cfg,
			[GPIOMUX_SUSPENDED] = &nc_irq_cfg,
		},
	},
#endif
	{
		.gpio		= 36,		/* NFC TX EN*/
		.settings = {
			[GPIOMUX_ACTIVE] = &nc_tx_en_cfg,
			[GPIOMUX_SUSPENDED] = &nc_tx_en_cfg,
		},
	},

};
#endif

static struct msm_gpiomux_config wcnss_5wire_interface[] = {
	{
		.gpio = 40,
		.settings = {
			[GPIOMUX_ACTIVE]    = &wcnss_5wire_active_cfg,
			[GPIOMUX_SUSPENDED] = &wcnss_5wire_suspend_cfg,
		},
	},
	{
		.gpio = 41,
		.settings = {
			[GPIOMUX_ACTIVE]    = &wcnss_5wire_active_cfg,
			[GPIOMUX_SUSPENDED] = &wcnss_5wire_suspend_cfg,
		},
	},
	{
		.gpio = 42,
		.settings = {
			[GPIOMUX_ACTIVE]    = &wcnss_5wire_active_cfg,
			[GPIOMUX_SUSPENDED] = &wcnss_5wire_suspend_cfg,
		},
	},
	{
		.gpio = 43,
		.settings = {
			[GPIOMUX_ACTIVE]    = &wcnss_5wire_active_cfg,
			[GPIOMUX_SUSPENDED] = &wcnss_5wire_suspend_cfg,
		},
	},
	{
		.gpio = 44,
		.settings = {
			[GPIOMUX_ACTIVE]    = &wcnss_5wire_active_cfg,
			[GPIOMUX_SUSPENDED] = &wcnss_5wire_suspend_cfg,
		},
	},
};

static struct gpiomux_setting gpio_suspend_config[] = {
	{
		.func = GPIOMUX_FUNC_GPIO,  /* IN-NP */
		.drv = GPIOMUX_DRV_2MA,
#if defined(CONFIG_MACH_MS01_CHN_CTC) || defined(CONFIG_MACH_CRATERVE_CHN_CTC)  || defined(CONFIG_MACH_S3VE_CHN_CTC)
		.pull = GPIOMUX_PULL_DOWN,
#else
		.pull = GPIOMUX_PULL_NONE,
#endif
	},
	{
		.func = GPIOMUX_FUNC_GPIO,  /* O-LOW */
		.drv = GPIOMUX_DRV_2MA,
		.pull = GPIOMUX_PULL_NONE,
		.dir = GPIOMUX_OUT_LOW,
	},
	{
		.func = GPIOMUX_FUNC_GPIO,  /* IN-PD */
		.drv = GPIOMUX_DRV_2MA,
		.pull = GPIOMUX_PULL_DOWN,
	},
};

static struct gpiomux_setting cam_settings[] = {
	{
		.func = GPIOMUX_FUNC_1, /*active 1*/ /* 0 */
		.drv = GPIOMUX_DRV_2MA,
		.pull = GPIOMUX_PULL_NONE,
	},

	{
		.func = GPIOMUX_FUNC_1, /*suspend*/ /* 1 */
		.drv = GPIOMUX_DRV_2MA,
		.pull = GPIOMUX_PULL_DOWN,
	},

	{
		.func = GPIOMUX_FUNC_1, /*i2c suspend*/ /* 2 */
		.drv = GPIOMUX_DRV_2MA,
		.pull = GPIOMUX_PULL_KEEPER,
	},

	{
		.func = GPIOMUX_FUNC_GPIO, /*active 0*/ /* 3 */
		.drv = GPIOMUX_DRV_2MA,
		.pull = GPIOMUX_PULL_NONE,
		.dir = GPIOMUX_OUT_LOW,
	},

	{
		.func = GPIOMUX_FUNC_GPIO, /*suspend 0*/ /* 4 */
		.drv = GPIOMUX_DRV_2MA,
		.pull = GPIOMUX_PULL_DOWN,
		.dir = GPIOMUX_OUT_LOW,
	},
	{
		.func = GPIOMUX_FUNC_1, /*active 1*/ /* 0 */
		.drv = GPIOMUX_DRV_4MA,
		.pull = GPIOMUX_PULL_NONE,
	},
	{
		.func = GPIOMUX_FUNC_1, /*suspend*/ /* 1 */
		.drv = GPIOMUX_DRV_4MA,
		.pull = GPIOMUX_PULL_DOWN,
	},
	{
		.func = GPIOMUX_FUNC_GPIO, /*active 1*/ /* 0 */ //7 Haarika
		.drv = GPIOMUX_DRV_2MA,
		.pull = GPIOMUX_PULL_DOWN,
		.dir = GPIOMUX_IN,
	},
	{
		.func = GPIOMUX_FUNC_GPIO, /*suspend*/ /* 1 */ //8
		.drv = GPIOMUX_DRV_2MA,
		.pull = GPIOMUX_PULL_DOWN,
		.dir = GPIOMUX_IN,
	},
	{
		.func = GPIOMUX_FUNC_1, /*active 1*/ /* 9 */
		.drv = GPIOMUX_DRV_6MA,
		.pull = GPIOMUX_PULL_NONE,
	},
	{
		.func = GPIOMUX_FUNC_1, /*suspend*/ /* 10 */
		.drv = GPIOMUX_DRV_6MA,
		.pull = GPIOMUX_PULL_DOWN,
	},
};

#if defined(CONFIG_MACH_HLITE_EUR_3GDS)
static struct gpiomux_setting gpio_cam_i2c_config = {
		.func = GPIOMUX_FUNC_3,
		.drv = GPIOMUX_DRV_2MA,
		.pull = GPIOMUX_PULL_DOWN,
};
#endif

static struct msm_gpiomux_config msm_sensor_configs[] __initdata = {
#if defined(CONFIG_MACH_CRATERQ) || defined(CONFIG_MACH_S3VE_CHN_CTC) || defined(CONFIG_MACH_S3VE_CHN_OPEN) || defined(CONFIG_MACH_S3VE_CHN_CMCC)
		{
			.gpio = 0, /* CIS_SPI_MOSI */
			.settings = {
				[GPIOMUX_ACTIVE]	= &cam_settings[5],
				[GPIOMUX_SUSPENDED] = &cam_settings[8],
			},
		},
		{
			.gpio = 1, /* CIS_SPI_MISO */
			.settings = {
				[GPIOMUX_ACTIVE]	= &cam_settings[5],
				[GPIOMUX_SUSPENDED] = &cam_settings[8],
			},
		},
		{
			.gpio = 2, /* CIS_SPI_SSN */
			.settings = {
				[GPIOMUX_ACTIVE]	= &cam_settings[5],
				[GPIOMUX_SUSPENDED] = &cam_settings[6],
			},
		},
		{
			.gpio = 3, /* CIS_SPI_SCLK */
			.settings = {
				[GPIOMUX_ACTIVE]	= &cam_settings[5],
				[GPIOMUX_SUSPENDED] = &cam_settings[8],
			},
		},
		{
			.gpio = 36, /* AF_SCL */
			.settings = {
				[GPIOMUX_ACTIVE]	= &cam_settings[0],
				[GPIOMUX_SUSPENDED] = &cam_settings[4],
			},
		},
#elif defined(CONFIG_MACH_HLITE_EUR_3GDS)
		{
			.gpio = 0, /* CIS_SPI_MOSI */
			.settings = {
				[GPIOMUX_ACTIVE]	= &gpio_spi_act_config,
				[GPIOMUX_SUSPENDED] = &gpio_spi_susp_config,
			},
		},
		{
			.gpio = 1, /* CIS_SPI_MISO */
			.settings = {
				[GPIOMUX_ACTIVE]	= &gpio_spi_act_config,
				[GPIOMUX_SUSPENDED] = &gpio_spi_susp_config,
			},
		},
		{
			.gpio = 2, /* CIS_SPI_SSN */
			.settings = {
				[GPIOMUX_ACTIVE]	= &gpio_spi_act_config,
				[GPIOMUX_SUSPENDED] = &gpio_spi_susp_config,
			},
		},
		{
			.gpio = 3, /* CIS_SPI_SCLK */
			.settings = {
				[GPIOMUX_ACTIVE]	= &gpio_spi_act_config,
				[GPIOMUX_SUSPENDED] = &gpio_spi_susp_config,
			},
		},
		{
			.gpio	   = 22,		/* VT_CAM_I2C_SDA */
			.settings = {
			[GPIOMUX_ACTIVE] = &gpio_cam_i2c_config,
			[GPIOMUX_SUSPENDED] = &gpio_suspend_config[2],
			},
		},
		{
			.gpio	   = 23,		/* VT_CAM_I2C_SCL */
			.settings = {
			[GPIOMUX_ACTIVE] = &gpio_cam_i2c_config,
			[GPIOMUX_SUSPENDED] = &gpio_suspend_config[2],
			},
		},
		{	
			.gpio = 10, /* CAM_VT_STBY*/
			.settings = {
				[GPIOMUX_ACTIVE] = &cam_settings[4],
				[GPIOMUX_SUSPENDED] = &gpio_suspend_config[2],
			},
		},
#endif
#if defined(CONFIG_MACH_MS01_LTE) || defined(CONFIG_MACH_MS01_EUR_3G)
	{
		.gpio = 26, /* CAM_MCLK0 */
		.settings = {
			[GPIOMUX_ACTIVE]    = &cam_settings[9],
			[GPIOMUX_SUSPENDED] = &cam_settings[10],
		},
	},

#else

	{
		.gpio = 26, /* CAM_MCLK0 */
		.settings = {
			[GPIOMUX_ACTIVE]    = &cam_settings[5],
			[GPIOMUX_SUSPENDED] = &cam_settings[6],
		},
	},

#endif
#if !defined(CONFIG_MACH_MS01_CHN_CTC) && !defined(CONFIG_MACH_CRATERVE_CHN_CTC) && !defined(CONFIG_MACH_MS01_EUR_3G) && !defined(CONFIG_MACH_CRATERQ) && !defined(CONFIG_MACH_MS01_CHN_CMCC_3G) && !defined(CONFIG_MACH_BAFFIN2_CHN_CMCC)
	{
		.gpio = 27, /* CAM_MCLK1 */
		.settings = {
			[GPIOMUX_ACTIVE]    = &cam_settings[5],
			[GPIOMUX_SUSPENDED] = &cam_settings[6],
		},

	},
#elif defined(CONFIG_MACH_MS01_EUR_3G) || defined(CONFIG_MACH_CRATERQ)|| defined(CONFIG_MACH_MS01_CHN_CMCC_3G)
	{
		.gpio = 27, /* CAM_MCLK1 */
		.settings = {
			[GPIOMUX_ACTIVE]    = &cam_settings[7],
			[GPIOMUX_SUSPENDED] = &cam_settings[8],
		},

	},
#endif 
	{
		.gpio = 29, /* CCI_I2C_SDA0 */
		.settings = {
			[GPIOMUX_ACTIVE]    = &cam_settings[1],
			[GPIOMUX_SUSPENDED] = &gpio_suspend_config[2],
		},
	},
	{
		.gpio = 30, /* CCI_I2C_SCL0 */
		.settings = {
			[GPIOMUX_ACTIVE]    = &cam_settings[1],
			[GPIOMUX_SUSPENDED] = &gpio_suspend_config[2],
		},
	},
#if !defined(CONFIG_MACH_MS01_CHN_CTC) && !defined(CONFIG_MACH_CRATERVE_CHN_CTC)
	{
		.gpio = 36, /* CAM1_STANDBY_N */
		.settings = {
			[GPIOMUX_ACTIVE]    = &cam_settings[3],
			[GPIOMUX_SUSPENDED] = &cam_settings[4],
		},
	},
#endif
	{
		.gpio = 37, /* CAM1_RST_N */
		.settings = {
			[GPIOMUX_ACTIVE]    = &cam_settings[3],
			[GPIOMUX_SUSPENDED] = &cam_settings[4],
		},
	},
#if !defined(CONFIG_MACH_MS01_CHN_CTC) && !defined(CONFIG_MACH_CRATERVE_CHN_CTC) && !defined(CONFIG_MACH_HLITE_EUR_3GDS)	
	{
		.gpio = 34, /* CAM1 VCM_PWDN */
		.settings = {
			[GPIOMUX_ACTIVE]    = &cam_settings[3],
			[GPIOMUX_SUSPENDED] = &cam_settings[4],
		},
	},
#endif
	{
		.gpio = 28, /* CAM2_RST_N */
		.settings = {
			[GPIOMUX_ACTIVE]    = &cam_settings[3],
			[GPIOMUX_SUSPENDED] = &cam_settings[4],
		},
	},
#if defined(CONFIG_MACH_HLITE_EUR_3GDS)
	{	
		.gpio = 88, /* CAM_VT_IO1.8 */
		.settings = {
			[GPIOMUX_ACTIVE]	= &cam_settings[3],
			[GPIOMUX_SUSPENDED] = &cam_settings[4],
		},
	},
	{	
		.gpio = 89, /* CAM_VT_A2.8*/
		.settings = {
			[GPIOMUX_ACTIVE]	= &cam_settings[3],
			[GPIOMUX_SUSPENDED] = &cam_settings[4],
		},
	},
#endif
/*
};

static struct msm_gpiomux_config msm_sensor_configs_skuf_plus[] __initdata = {*/
	{
		.gpio = 112, /* CAM_ANALOG_EN */
		.settings = {
			[GPIOMUX_ACTIVE]    = &cam_settings[3],
			[GPIOMUX_SUSPENDED] = &cam_settings[4],
		},
	},
#if !defined(CONFIG_MACH_S3VE_CHN_OPEN) && !defined(CONFIG_MACH_S3VE_CHN_CMCC)
	{
		.gpio = 114, /* CAM_IO_EN */
		.settings = {
			[GPIOMUX_ACTIVE]    = &cam_settings[3],
			[GPIOMUX_SUSPENDED] = &cam_settings[4],
		},
	},
#endif
#if defined(CONFIG_MACH_CRATERQ)
	{
		.gpio = 32, /* FLASH_STROBE_TRIG */
		.settings = {
			[GPIOMUX_ACTIVE]    = &cam_settings[7],
			[GPIOMUX_SUSPENDED] = &cam_settings[7],
		},
	},
	{
		.gpio = 67, /* CAM_CORE_EN */
		.settings = {
			[GPIOMUX_ACTIVE]    = &cam_settings[3],
			[GPIOMUX_SUSPENDED] = &cam_settings[3],
		},
	},
	{
		.gpio = 74,
		.settings = {
			[GPIOMUX_ACTIVE]    = &cam_settings[3],
			[GPIOMUX_SUSPENDED] = &cam_settings[4],
		},
	},
#endif	
#if defined(CONFIG_I2C_ACTUATOR)
#if defined(CONFIG_MACH_HLITE_EUR_3GDS)
		{
			.gpio = 74, /* AF_SCL */
			.settings = {
			[GPIOMUX_ACTIVE] = &cam_settings[4],
			[GPIOMUX_SUSPENDED] = &gpio_suspend_config [2],
			},
		},
		{
			.gpio = 11, /* AF_SDA */
			.settings = {
			[GPIOMUX_ACTIVE] = &cam_settings[4],
			[GPIOMUX_SUSPENDED] = &gpio_suspend_config[2],
			},
		},
#else
	{
		.gpio      = 34, /* AF_SDA */
		.settings = {
			/*[GPIOMUX_ACTIVE] = &gpio_i2c_config,*/
			[GPIOMUX_SUSPENDED] = &gpio_suspend_config[0],
		},
	},
	{
		.gpio      = 33, /* AF_SCL */
		.settings = {
			/*[GPIOMUX_ACTIVE] = &gpio_i2c_config,*/
			[GPIOMUX_SUSPENDED] = &gpio_suspend_config[0],
		},
	},
#endif
#endif

};


#if defined (CONFIG_SAMSUNG_JACK)
static struct gpiomux_setting earjack_gpio_active_cfg = {
	.func = GPIOMUX_FUNC_GPIO, /*active 1*/ /* 0 */
	.drv = GPIOMUX_DRV_2MA,
#if defined(CONFIG_MACH_MILLET3G_EUR) || defined(CONFIG_MACH_CRATERQ)
	.pull = GPIOMUX_PULL_NONE,
#else
	.pull = GPIOMUX_PULL_DOWN,
#endif
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting earjack_gpio_suspend_cfg = {
	.func = GPIOMUX_FUNC_GPIO, /*suspend*/ /* 1 */
	.drv = GPIOMUX_DRV_2MA,
#if defined(CONFIG_MACH_MILLET3G_EUR) || defined(CONFIG_MACH_CRATERQ)
	.pull = GPIOMUX_PULL_NONE,
#else
	.pull = GPIOMUX_PULL_DOWN,
#endif
	.dir = GPIOMUX_IN,
};

static struct msm_gpiomux_config msm_earjack_gpio_configs[] __initdata = {
	{
#if defined(CONFIG_MACH_MILLET3G_EUR)
		.gpio = 111, /* EAR_SEND_END */
#else
		.gpio = 35, /* EAR_SWITCH */
#endif
		.settings = {
			[GPIOMUX_ACTIVE]    = &earjack_gpio_active_cfg,
			[GPIOMUX_SUSPENDED] = &earjack_gpio_suspend_cfg,
		},
	}
};
#endif

#if defined(CONFIG_MACH_MILLET3G_EUR)
static struct gpiomux_setting speaker_enable_gpio_active_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_4MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting speaker_enable_gpio_suspend_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};

static struct msm_gpiomux_config msm_speaker_enable_gpio_configs[] __initdata = {
	{
		.gpio = 24,
		.settings = {
			[GPIOMUX_ACTIVE]    = &speaker_enable_gpio_active_cfg,
			[GPIOMUX_SUSPENDED] = &speaker_enable_gpio_suspend_cfg,
		},
	},
};
#endif

#if !defined(CONFIG_MACH_HLITE_EUR_3GDS)
static struct gpiomux_setting usb_otg_sw_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.dir = GPIOMUX_OUT_LOW,
};

static struct msm_gpiomux_config usb_otg_sw_configs[] __initdata = {
	{
		.gpio = 67,
		.settings = {
			[GPIOMUX_SUSPENDED] = &usb_otg_sw_cfg,
		},
	},
};
#endif

#if defined(CONFIG_MACH_CRATERQ)
static struct gpiomux_setting lcd_connected = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.dir = GPIOMUX_IN,
	.pull = GPIOMUX_PULL_UP,
};

static struct msm_gpiomux_config lcd_connected_configs[] __initdata = {
	{
		.gpio = 23,
		.settings = {
               		[GPIOMUX_ACTIVE]    = &lcd_connected,
			[GPIOMUX_SUSPENDED] = &lcd_connected,
		},
	},
};
#endif

#ifdef CONFIG_MMC_MSM_SDC3_SUPPORT
static struct gpiomux_setting sdc3_clk_actv_cfg = {
	.func = GPIOMUX_FUNC_2,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_NONE,
};

static struct gpiomux_setting sdc3_cmd_data_0_3_actv_cfg = {
	.func = GPIOMUX_FUNC_2,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting sdc3_suspend_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
};

static struct gpiomux_setting sdc3_data_1_suspend_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct msm_gpiomux_config msm8226_sdc3_configs[] __initdata = {
	{
		/* DAT3 */
		.gpio      = 39,
		.settings = {
			[GPIOMUX_ACTIVE]    = &sdc3_cmd_data_0_3_actv_cfg,
			[GPIOMUX_SUSPENDED] = &sdc3_suspend_cfg,
		},
	},
	{
		/* DAT2 */
		.gpio      = 40,
		.settings = {
			[GPIOMUX_ACTIVE]    = &sdc3_cmd_data_0_3_actv_cfg,
			[GPIOMUX_SUSPENDED] = &sdc3_suspend_cfg,
		},
	},
	{
		/* DAT1 */
		.gpio      = 41,
		.settings = {
			[GPIOMUX_ACTIVE]    = &sdc3_cmd_data_0_3_actv_cfg,
			[GPIOMUX_SUSPENDED] = &sdc3_data_1_suspend_cfg,
		},
	},
	{
		/* DAT0 */
		.gpio      = 42,
		.settings = {
			[GPIOMUX_ACTIVE]    = &sdc3_cmd_data_0_3_actv_cfg,
			[GPIOMUX_SUSPENDED] = &sdc3_suspend_cfg,
		},
	},
	{
		/* CMD */
		.gpio      = 43,
		.settings = {
			[GPIOMUX_ACTIVE]    = &sdc3_cmd_data_0_3_actv_cfg,
			[GPIOMUX_SUSPENDED] = &sdc3_suspend_cfg,
		},
	},
	{
		/* CLK */
		.gpio      = 44,
		.settings = {
			[GPIOMUX_ACTIVE]    = &sdc3_clk_actv_cfg,
			[GPIOMUX_SUSPENDED] = &sdc3_suspend_cfg,
		},
	},
};

static void msm_gpiomux_sdc3_install(void)
{
	msm_gpiomux_install(msm8226_sdc3_configs,
			    ARRAY_SIZE(msm8226_sdc3_configs));
}
#else
static void msm_gpiomux_sdc3_install(void) {}
#endif /* CONFIG_MMC_MSM_SDC3_SUPPORT */

#ifdef CONFIG_LEDS_AN30259A
	static struct gpiomux_setting an30259a_i2c_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_NONE,
};


#if defined(CONFIG_MACH_HLITE_EUR_3GDS)
static struct msm_gpiomux_config an30259a_led_config[] __initdata = {
	{
		.gpio	= 7,		/* SVC_LED_SCL */
		.settings = {
			[GPIOMUX_ACTIVE] = &an30259a_i2c_config,
		},
	},
	{
		.gpio	= 6,		/* SVC_LED_SDA */
		.settings = {
			[GPIOMUX_ACTIVE] = &an30259a_i2c_config,
		},
	},
};
#else
static struct msm_gpiomux_config an30259a_led_config[] __initdata = {
	{
		.gpio	= 16,		/* SVC_LED_SCL */
		.settings = {
			[GPIOMUX_ACTIVE] = &an30259a_i2c_config,
		},
	},
	{
		.gpio	= 23,		/* SVC_LED_SDA */
		.settings = {
			[GPIOMUX_ACTIVE] = &an30259a_i2c_config,
		},
	},
};
#endif
#endif

#if defined(CONFIG_MACH_MS01_EUR_3G) || defined(CONFIG_MACH_CRATERQ) || defined(CONFIG_MACH_MS01_LTE) || defined(CONFIG_MACH_MS01_CHN_CTC) \
    || defined(CONFIG_MACH_MS01_LTE_KOR) || defined(CONFIG_MACH_CRATERVE_CHN_CTC)||defined (CONFIG_MACH_MS01_CHN_CMCC_3G)
static struct gpiomux_setting tx_gtr_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_OUT_LOW,
};
static struct msm_gpiomux_config msm8226_tx_gtr_configs[] __initdata = {
	{
		/* TX_GTR_THRESH */
		.gpio      = 87,
		.settings = {
			[GPIOMUX_ACTIVE]    = &tx_gtr_cfg,
			[GPIOMUX_SUSPENDED] = &tx_gtr_cfg,
		},
	},
};
#endif

#if defined(CONFIG_MACH_CRATERQ)
#define FAST_GPIO_CONFIG(gpio_num, suspend_cfg, active_cfg) { \
		.gpio = gpio_num, \
		.settings = { \
			[GPIOMUX_ACTIVE]    = &active_cfg, \
			[GPIOMUX_SUSPENDED] = &suspend_cfg, \
		} \
	}

static struct gpiomux_setting default_cfg_inp_np = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};

static struct gpiomux_setting codec_int_gpio_active_cfg = {
	.func = GPIOMUX_FUNC_GPIO, 
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting codec_int_gpio_suspend_cfg = {
	.func = GPIOMUX_FUNC_GPIO, 
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting ear_det_gpio_active_cfg = {
	.func = GPIOMUX_FUNC_GPIO, 
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting ear_det_gpio_suspend_cfg = {
	.func = GPIOMUX_FUNC_GPIO, 
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting codec_reset_gpio_active_cfg = {
	.func = GPIOMUX_FUNC_GPIO, 
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_OUT_LOW,
};

static struct gpiomux_setting codec_reset_gpio_suspend_cfg = {
	.func = GPIOMUX_FUNC_GPIO, 
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_OUT_LOW,
};

static struct gpiomux_setting motor_en_gpio_active_cfg = {
	.func = GPIOMUX_FUNC_GPIO, 
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_OUT_LOW,
};

static struct gpiomux_setting motor_en_gpio_suspend_cfg = {
	.func = GPIOMUX_FUNC_GPIO, 
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_OUT_LOW,
};

static struct msm_gpiomux_config craterq_gpio_configs[] __initdata = {
	/* ETC */
	FAST_GPIO_CONFIG(14, default_cfg_inp_np, default_cfg_inp_np), /* HW_CHK_BIT1 */
	FAST_GPIO_CONFIG(15, default_cfg_inp_np, default_cfg_inp_np), /* HW_CHK_BIT0 */
	FAST_GPIO_CONFIG(22, default_cfg_inp_np, default_cfg_inp_np), /* CHECK_DS_SS */
	FAST_GPIO_CONFIG(51, default_cfg_inp_np, default_cfg_inp_np), /* CHG_DET */
	/* AUDIO */
	FAST_GPIO_CONFIG(68, codec_int_gpio_suspend_cfg  , codec_int_gpio_active_cfg),
	FAST_GPIO_CONFIG(69, ear_det_gpio_suspend_cfg    , ear_det_gpio_active_cfg),
	FAST_GPIO_CONFIG(72, codec_reset_gpio_suspend_cfg, codec_reset_gpio_active_cfg),
	FAST_GPIO_CONFIG(111, motor_en_gpio_suspend_cfg  , motor_en_gpio_active_cfg),
};
#endif

#if defined(CONFIG_MACH_HLITE_EUR_3GDS)
static struct gpiomux_setting tx_wtr_cfg = {
	 .func = GPIOMUX_FUNC_GPIO,
	 .drv = GPIOMUX_DRV_2MA,
	 .pull = GPIOMUX_PULL_DOWN,
	 .dir = GPIOMUX_IN,
};

static struct msm_gpiomux_config msm_esd_configs[] __initdata = {
	{
		/* OLED_DET */
		.gpio      = 34,
		.settings = {
			[GPIOMUX_ACTIVE]    = &tx_wtr_cfg,
			[GPIOMUX_SUSPENDED] = &tx_wtr_cfg,
		},
	},
};
#endif

#if defined(CONFIG_MACH_MS01_CHN_CTC)
static struct msm_gpiomux_config msm8226_nc_gpio_cfgs[] __initdata = {
	NC_GPIO_CONFIG(24),
	NC_GPIO_CONFIG(49),
	NC_GPIO_CONFIG(67),
};
#elif defined(CONFIG_MACH_MS01_EUR_3G)
static struct msm_gpiomux_config msm8226_nc_gpio_cfgs[] __initdata = {
	NC_GPIO_CONFIG(23),
	NC_GPIO_CONFIG(49),
	NC_GPIO_CONFIG(67),
};
#elif defined(CONFIG_MACH_CRATERQ)
static struct msm_gpiomux_config msm8226_nc_gpio_cfgs[] __initdata = {
	NC_GPIO_CONFIG(10),
	NC_GPIO_CONFIG(16),
	NC_GPIO_CONFIG(11),
	GPIO_IN_NP_CONFIG(23),
	GPIO_IN_NP_CONFIG(36),
	NC_GPIO_CONFIG(50),
	NC_GPIO_CONFIG(56),
	NC_GPIO_CONFIG(60),
	GPIO_IN_NP_CONFIG(62),
	NC_GPIO_CONFIG(80),
};
#elif defined(CONFIG_MACH_CRATERVE_CHN_CTC)
static struct msm_gpiomux_config msm8226_nc_gpio_cfgs[] __initdata = {
	NC_GPIO_CONFIG(24), 
	NC_GPIO_CONFIG(67),
};
#elif defined(CONFIG_MACH_MS01_CHN_CMCC_3G)
static struct msm_gpiomux_config msm8226_nc_gpio_cfgs[] __initdata = {
	NC_GPIO_CONFIG(23),
	NC_GPIO_CONFIG(67),
};
#elif defined(CONFIG_MACH_S3VE_CHN_OPEN) || defined(CONFIG_MACH_S3VE_CHN_CMCC)
static struct msm_gpiomux_config msm8226_nc_gpio_cfgs[] __initdata = {
	NC_GPIO_CONFIG(60),
};
#elif defined(CONFIG_MACH_BAFFIN2_CHN_CMCC)
static struct msm_gpiomux_config msm8226_nc_gpio_cfgs[] __initdata = {
	NC_GPIO_CONFIG(53),
	NC_GPIO_CONFIG(54),
	NC_GPIO_CONFIG(55),
	NC_GPIO_CONFIG(67),
	NC_GPIO_CONFIG(80),
};
#endif

#if defined(CONFIG_MACH_MS01_EUR_3G)
static struct msm_gpiomux_config ms01_nc_gpio_cfgs[] __initdata = {
	NC_GPIO_CONFIG(10),
	NC_GPIO_CONFIG(11),
};
#endif

#if defined(CONFIG_MACH_HLITE_EUR_3GDS)
static struct msm_gpiomux_config msm8226_nc_gpio_cfgs[] __initdata = {
	NC_GPIO_CONFIG(45),
	NC_GPIO_CONFIG(46),
	NC_GPIO_CONFIG(73),
	NC_GPIO_CONFIG(91),
	NC_GPIO_CONFIG(97),
	NC_GPIO_CONFIG(98),
};
#endif

#if defined(CONFIG_MACH_MS01_CHN_CTC) 
static struct msm_gpiomux_config ms01_ctc_nc_gpio_cfgs[] __initdata = {
	NC_GPIO_CONFIG(22),
	NC_GPIO_CONFIG(23),
};
#elif defined(CONFIG_MACH_CRATERVE_CHN_CTC)
static struct msm_gpiomux_config ms01_ctc_nc_gpio_cfgs[] __initdata = { 
	NC_GPIO_CONFIG(23),
};
#endif

/* #ifdef CONFIG_SND_SOC_MAX98504 */
#if defined(CONFIG_MACH_CRATERQ)
static struct gpiomux_setting gpio_i2c_codec_active_config = {
	.func = GPIOMUX_FUNC_3,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};
static struct gpiomux_setting gpio_i2c_codec_suspend_config = {
	.func = GPIOMUX_FUNC_3,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
};

static struct gpiomux_setting  pri_mi2s_act_cfg = {
	.func = GPIOMUX_FUNC_1,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_IN,
};

static struct gpiomux_setting  pri_mi2s_sus_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_IN,
};

static struct msm_gpiomux_config msm8226_blsp_codec_configs[] __initdata = {
	{					/*  MAX_SDA   */
		.gpio      = 10,		/* BLSP1 QUP3 I2C_DAT */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_i2c_codec_active_config,
			[GPIOMUX_SUSPENDED] = &gpio_i2c_codec_suspend_config,
		},
	},
	{					/*  MAX_SCL   */
		.gpio      = 11,		/* BLSP1 QUP3 I2C_CLK */
		.settings = {
			[GPIOMUX_ACTIVE] = &gpio_i2c_codec_active_config,
			[GPIOMUX_SUSPENDED] = &gpio_i2c_codec_suspend_config,
		},
	},
};

static struct msm_gpiomux_config msm8226_tertiary_mi2s_configs[] __initdata = {
	{
		.gpio	= 49,		/* qua mi2s sck */
		.settings = {
			[GPIOMUX_SUSPENDED] = &pri_mi2s_sus_cfg,
			[GPIOMUX_ACTIVE] = &pri_mi2s_act_cfg,
		},
	},
	{
		.gpio	= 50,
		.settings = {
			[GPIOMUX_SUSPENDED] = &pri_mi2s_sus_cfg,
			[GPIOMUX_ACTIVE] = &pri_mi2s_act_cfg,
		},
	},
	{
		.gpio = 51,
		.settings = {
			[GPIOMUX_SUSPENDED] = &pri_mi2s_sus_cfg,
			[GPIOMUX_ACTIVE] = &pri_mi2s_act_cfg,
		},
	},
	{
		.gpio = 52,
		.settings = {
			[GPIOMUX_SUSPENDED] = &pri_mi2s_sus_cfg,
			[GPIOMUX_ACTIVE] = &pri_mi2s_act_cfg,
		},
	},

};
#endif

#if defined(CONFIG_MACH_BAFFIN2_CHN_CMCC)
static struct gpiomux_setting qsc_ipc_output_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_UP,
	.dir = GPIOMUX_OUT_HIGH,
};

#if 1
static struct gpiomux_setting qsc_ipc_input_pd_cfg = {
	.func = GPIOMUX_FUNC_GPIO, 
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
	.dir = GPIOMUX_IN,
};
#endif 

static struct gpiomux_setting qsc_ipc_input_np_cfg = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIOMUX_IN,
};

static struct msm_gpiomux_config msm8226_qsc_ipc_configs_rev02[] __initdata = {
#if 1
	{
		
		.gpio	   = 27,
		.settings = {
			//[GPIOMUX_ACTIVE]	= &mdm2ap_status_cfg,
			[GPIOMUX_SUSPENDED] = &qsc_ipc_input_pd_cfg,
		},
	},
#endif
	{
		
		.gpio	   = 49,
		.settings = {
			//[GPIOMUX_ACTIVE]	= &qsc_ipc_input_pd_cfg,
			[GPIOMUX_SUSPENDED] = &qsc_ipc_input_np_cfg,
		},
	},
	{
	
		.gpio      = 93,
		.settings = {
			//[GPIOMUX_ACTIVE]    = &qsc_ipc_output_cfg,
			[GPIOMUX_SUSPENDED] = &qsc_ipc_output_cfg,
		},
	},
	{
	
		.gpio      = 110,
		.settings = {
			//[GPIOMUX_ACTIVE]    = &qsc_ipc_output_cfg,
			[GPIOMUX_SUSPENDED] = &qsc_ipc_output_cfg,
		},
	},
	{
	
		.gpio      = 115,
		.settings = {
			//[GPIOMUX_ACTIVE]    = &qsc_ipc_output_cfg,
			[GPIOMUX_SUSPENDED] = &qsc_ipc_output_cfg,
		},
	},
};

static struct msm_gpiomux_config msm8226_qsc_ipc_configs_rev03[] __initdata = {
#if 1
	{
		
		.gpio	   = 27,
		.settings = {
			//[GPIOMUX_ACTIVE]	= &mdm2ap_status_cfg,
			[GPIOMUX_SUSPENDED] = &qsc_ipc_input_pd_cfg,
		},
	},
#endif
	{
		
		.gpio	   = 49,
		.settings = {
			//[GPIOMUX_ACTIVE]	= &qsc_ipc_input_pd_cfg,
			[GPIOMUX_SUSPENDED] = &qsc_ipc_input_np_cfg,
		},
	},
	{
	
		.gpio      = 93,
		.settings = {
			//[GPIOMUX_ACTIVE]    = &qsc_ipc_output_cfg,
			[GPIOMUX_SUSPENDED] = &qsc_ipc_output_cfg,
		},
	},
	{
	
		.gpio      = 73,
		.settings = {
			//[GPIOMUX_ACTIVE]    = &qsc_ipc_output_cfg,
			[GPIOMUX_SUSPENDED] = &qsc_ipc_output_cfg,
		},
	},
	{
		.gpio      = 115,
		.settings = {
			//[GPIOMUX_ACTIVE]    = &qsc_ipc_output_cfg,
			[GPIOMUX_SUSPENDED] = &qsc_ipc_output_cfg,
		},
	},
};

static struct gpiomux_setting external_vfr[] = {
	/* Suspended state */
	{
		.func = GPIOMUX_FUNC_2,
		.drv = GPIOMUX_DRV_2MA,
		.pull = GPIOMUX_PULL_KEEPER,
	},
	/* Active state */
	{
		.func = GPIOMUX_FUNC_2,
		.drv = GPIOMUX_DRV_2MA,
		.pull = GPIOMUX_PULL_KEEPER,
	},
};

static struct msm_gpiomux_config msm8226_external_vfr_configs[] __initdata = {
	{
		.gpio      = 38,        /* EXTERNAL VFR */
		.settings = {
			[GPIOMUX_SUSPENDED] = &external_vfr[0],
			[GPIOMUX_ACTIVE] = &external_vfr[1],
		},
	},
};
#endif


#if defined(CONFIG_MACH_MS01_CHN_CTC) || defined(CONFIG_MACH_CRATERVE_CHN_CTC) || defined(CONFIG_MACH_BAFFIN2_CHN_CMCC) || defined(CONFIG_MACH_CRATERQ)
extern unsigned int system_rev; 
#endif

void __init msm8226_init_gpiomux(void)
{
	int rc;

	rc = msm_gpiomux_init_dt();
	if (rc) {
		pr_err("%s failed %d\n", __func__, rc);
		return;
	}

#if defined(CONFIG_KS8851) || defined(CONFIG_KS8851_MODULE)
	msm_gpiomux_install(msm_eth_configs, ARRAY_SIZE(msm_eth_configs));
#endif
	msm_gpiomux_install(msm_keypad_configs,
			ARRAY_SIZE(msm_keypad_configs));

#if defined(CONFIG_MACH_MS01_EUR_3G) || defined(CONFIG_MACH_MS01_LTE) || defined(CONFIG_MACH_MILLET3G_EUR) || defined(CONFIG_MACH_MS01_CHN_CTC) \
    || defined(CONFIG_MACH_MS01_LTE_KOR) || defined(CONFIG_MACH_CRATERVE_CHN_CTC) || defined(CONFIG_MACH_S3VE)|| defined(CONFIG_MACH_MS01_CHN_CMCC_3G) \
    || defined(CONFIG_MACH_HLITE_EUR_3GDS)
	msm_gpiomux_install(msm_hall_configs,
			ARRAY_SIZE(msm_hall_configs));
#endif

	if (of_board_is_qrd())
		msm_gpiomux_install(msm_qrd_blsp_configs,
			ARRAY_SIZE(msm_qrd_blsp_configs));
	else
		msm_gpiomux_install(msm_blsp_configs,
			ARRAY_SIZE(msm_blsp_configs));

	msm_gpiomux_install(wcnss_5wire_interface,
				ARRAY_SIZE(wcnss_5wire_interface));

#if defined(CONFIG_MACH_BAFFIN2_CHN_CMCC)
	if(system_rev >= 6)
		msm_gpiomux_install(&baffin2_cmcc_sd_card_det_rev06, 1);
	else if(system_rev <  3)
		msm_gpiomux_install(&sd_card_det, 1);	
	else
		msm_gpiomux_install(&baffin2_cmcc_sd_card_det, 1);
#else
	msm_gpiomux_install(&sd_card_det, 1);
#endif

#if defined(CONFIG_MACH_MS01_EUR_3G) || defined(CONFIG_MACH_CRATERQ) || defined(CONFIG_MACH_MS01_LTE) || defined(CONFIG_MACH_MS01_CHN_CTC) \
    || defined(CONFIG_MACH_MS01_LTE_KOR) || defined(CONFIG_MACH_CRATERVE_CHN_CTC)|| defined(CONFIG_MACH_MS01_CHN_CMCC_3G)
		msm_gpiomux_install(msm8226_tx_gtr_configs,
					ARRAY_SIZE(msm8226_tx_gtr_configs));
		msm_gpiomux_install(muic_i2c_configs,
					ARRAY_SIZE(muic_i2c_configs));
#elif defined(CONFIG_MACH_S3VE_CHN_OPEN) || defined(CONFIG_MACH_S3VE_CHN_CMCC) || defined(CONFIG_MACH_HLITE_EUR_3GDS)
		msm_gpiomux_install(muic_i2c_configs,
					ARRAY_SIZE(muic_i2c_configs));
#endif

	if (of_board_is_qrd())
		msm_gpiomux_install(msm_qrd_goodix_configs,
				ARRAY_SIZE(msm_qrd_goodix_configs));

	else
#if defined(CONFIG_TOUCHSCREEN_ZINITIX_BT531)
		msm_gpiomux_install(msm_zinitixs_configs,
			ARRAY_SIZE(msm_zinitixs_configs));
#elif defined(CONFIG_TOUCHSCREEN_ATMEL_MXTS)
		msm_gpiomux_install(msm_atmel_configs,
			ARRAY_SIZE(msm_atmel_configs));
#elif defined(CONFIG_TOUCHSCREEN_MMS144)
		msm_gpiomux_install(msm_melfas_configs,
			ARRAY_SIZE(msm_melfas_configs));
#elif defined(CONFIG_TOUCHSCREEN_SYNAPTICS_I2C_RMI4)
		msm_gpiomux_install(msm_synaptics_configs,
			ARRAY_SIZE(msm_synaptics_configs));
#else
		msm_gpiomux_install(msm_tsp_default_configs,
			ARRAY_SIZE(msm_tsp_default_configs));

#endif
#if defined (CONFIG_MACH_CRATERQ)
//	msm_gpiomux_install(msm_lcd_write_configs,
//			ARRAY_SIZE(msm_lcd_write_configs));
	msm_gpiomux_install_nowrite(msm_lcd_nowrite_configs,
			ARRAY_SIZE(msm_lcd_nowrite_configs));
#endif

	if (of_board_is_skuf())
		msm_gpiomux_install(msm_skuf_nfc_configs,
				ARRAY_SIZE(msm_skuf_nfc_configs));

#if defined(CONFIG_FB_MSM_MDSS_SHARP_HD_PANEL)\
	|| defined(CONFIG_MACH_MILLET3G_EUR)
	msm_gpiomux_install_nowrite(msm_lcd_configs,
			ARRAY_SIZE(msm_lcd_configs));
#endif
	msm_gpiomux_install(msm_sensor_configs, ARRAY_SIZE(msm_sensor_configs));
/*
	if (of_board_is_skuf())
		msm_gpiomux_install(msm_sensor_configs_skuf_plus,
			ARRAY_SIZE(msm_sensor_configs_skuf_plus));
*/
#if defined(CONFIG_MACH_MILLET3G_EUR)
	msm_gpiomux_install(msm_speaker_enable_gpio_configs, ARRAY_SIZE(msm_speaker_enable_gpio_configs));
#endif
#if defined(CONFIG_SEC_NFC_I2C) || defined(CONFIG_BCM2079X_NFC_I2C) || defined(CONFIG_NFC_PN547)
	msm_gpiomux_install(msm_nfc_configs,
		ARRAY_SIZE(msm_nfc_configs));

#else
	msm_gpiomux_install(msm_nc_configs,
	ARRAY_SIZE(msm_nc_configs));
#endif

#if defined(CONFIG_YAS_ACC_DRIVER_BMA250) || defined(CONFIG_INPUT_MPU6500) || \
defined(CONFIG_PROXIMITY_SENSOR) || defined (CONFIG_SENSORS_HSCDTD008A) || \
defined(CONFIG_SENSORS_INVENSENSE) || defined(CONFIG_SENSORS_TMD27723) || \
defined(CONFIG_SENSORS_AK09911C)
	msm_gpiomux_install(msm_sensors_configs,
		ARRAY_SIZE(msm_sensors_configs));
#endif

#if !defined(CONFIG_MACH_HLITE_EUR_3GDS)
	if (of_board_is_cdp() || of_board_is_mtp() || of_board_is_xpm())
		msm_gpiomux_install(usb_otg_sw_configs,
					ARRAY_SIZE(usb_otg_sw_configs));
#endif

	msm_gpiomux_sdc3_install();
	/*
	 * HSIC STROBE gpio is also used by the ethernet. Install HSIC
	 * gpio mux config only when HSIC is enabled. HSIC config will
	 * be disabled when ethernet config is enabled.
	 */
#ifdef CONFIG_USB_EHCI_MSM_HSIC
	if (machine_is_msm8926()) {
		msm_hsic_configs[0].gpio = 119; /* STROBE */
		msm_hsic_configs[1].gpio = 120; /* DATA */
	}
	msm_gpiomux_install(msm_hsic_configs, ARRAY_SIZE(msm_hsic_configs));
#endif
#if defined(CONFIG_LEDS_AN30259A)
	msm_gpiomux_install(an30259a_led_config,
				ARRAY_SIZE(an30259a_led_config));
#endif

#if defined(CONFIG_MACH_MS01_CHN_CTC) || defined(CONFIG_MACH_CRATERVE_CHN_CTC)||defined(CONFIG_MACH_MS01_EUR_3G)  ||\
	defined(CONFIG_MACH_CRATERQ)|| defined(CONFIG_MACH_MS01_CHN_CMCC_3G) || defined(CONFIG_MACH_S3VE_CHN_OPEN) || defined(CONFIG_MACH_S3VE_CHN_CMCC) || \
	defined(CONFIG_MACH_HLITE_EUR_3GDS) || defined(CONFIG_MACH_BAFFIN2_CHN_CMCC)
	msm_gpiomux_install(msm8226_nc_gpio_cfgs, ARRAY_SIZE(msm8226_nc_gpio_cfgs));
#endif

#if defined(CONFIG_SAMSUNG_JACK)
	msm_gpiomux_install(msm_earjack_gpio_configs, ARRAY_SIZE(msm_earjack_gpio_configs));
#endif
#if defined(CONFIG_MACH_MS01_EUR_3G)
	msm_gpiomux_install(ms01_nc_gpio_cfgs, ARRAY_SIZE(ms01_nc_gpio_cfgs));
#endif
#if defined(CONFIG_MACH_HLITE_EUR_3GDS)
	msm_gpiomux_install(chg_pm8226_configs, ARRAY_SIZE(chg_pm8226_configs));
	msm_gpiomux_install(hw_chk_bit_configs, ARRAY_SIZE(hw_chk_bit_configs));
#endif

#if defined(CONFIG_MACH_MS01_CHN_CTC) || defined(CONFIG_MACH_CRATERVE_CHN_CTC)
	if ( system_rev >= 4 ) {
		msm_gpiomux_install(ms01_ctc_nc_gpio_cfgs, ARRAY_SIZE(ms01_ctc_nc_gpio_cfgs));
	}
#elif defined(CONFIG_MACH_CRATERQ)
	msm_gpiomux_install(craterq_gpio_configs, ARRAY_SIZE(craterq_gpio_configs));
#endif

#if defined(CONFIG_MACH_CRATERQ)
	/* #ifdef CONFIG_SND_SOC_MAX98504 */
	if ( system_rev >= 4 ) {
		msm_gpiomux_install(msm8226_tertiary_mi2s_configs,ARRAY_SIZE(msm8226_tertiary_mi2s_configs));
		msm_gpiomux_install(msm8226_blsp_codec_configs,ARRAY_SIZE(msm8226_blsp_codec_configs));
	}
#endif

#if defined(CONFIG_MACH_BAFFIN2_CHN_CMCC)
	if ( system_rev == 2 ) {
		msm_gpiomux_install(msm8226_qsc_ipc_configs_rev02, ARRAY_SIZE(msm8226_qsc_ipc_configs_rev02));
	}else if ( system_rev >= 3 ) {
		msm_gpiomux_install(msm8226_qsc_ipc_configs_rev03, ARRAY_SIZE(msm8226_qsc_ipc_configs_rev03));
	}

	/* For msm8226 External VFR */
	if(system_rev >= 3)	{
		msm_gpiomux_install(msm8226_external_vfr_configs,
				ARRAY_SIZE(msm8226_external_vfr_configs));
	}
#endif

#if defined(CONFIG_MACH_CRATERQ)
	msm_gpiomux_install(lcd_connected_configs,	ARRAY_SIZE(lcd_connected_configs));
#endif
#if defined(CONFIG_MACH_HLITE_EUR_3GDS)
	msm_gpiomux_install(msm_esd_configs, ARRAY_SIZE(msm_esd_configs));
#endif
}

