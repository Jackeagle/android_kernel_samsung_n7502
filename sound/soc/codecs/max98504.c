/*
 * max98504.c -- MAX98504 ALSA SoC Audio driver
 *
 * Copyright 2011-2012 Maxim Integrated Products
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <sound/q6adm-v2.h>
#ifdef USE_DSM_LOG
#include <linux/time.h>
#endif
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/tlv.h>
#include <sound/max98504.h>
#include "max98504.h"
#include <linux/version.h>

#define SUPPORT_DEVICE_TREE
#define USE_DSM_MISC_DEV
//#define DEBUG_MAX98504
#define USE_SHDN_BY_ALSA_UCM
//#define DSM_ALWAYS_ON

#ifdef SUPPORT_DEVICE_TREE
#include <linux/regulator/consumer.h>
#endif

#ifdef DEBUG_MAX98504
#define msg_maxim(format, args...)	\
	printk(KERN_INFO "[MAX98504_DEBUG] %s " format, __func__, ## args)
#else
#define msg_maxim(format, args...)
#endif

#ifdef USE_DSM_MISC_DEV
enum	{
	param_voice_coil_temp=0,	// 0
	param_voice_coil_temp_sz,	// 1
	param_excursion,			// 2
	param_excursion_sz,			// 3
	param_rdc,					// 4
	param_rdc_sz,				// 5
	param_q,					// 6
	param_q_sz,					// 7
	param_fres,					// 8
	param_fres_sz,				// 9
	param_excur_limit,			// 10
	param_excur_limit_sz,		// 11
	param_voice_coil,			// 12
	param_voice_coil_sz,		// 13
	param_thermal_limit,		// 14
	param_thermal_limit_sz,		// 15
	param_release_time, 		// 16
	param_release_time_sz,		// 17
	param_onoff,				// 18
	param_onoff_sz,				// 19
	param_static_gain,			// 20
	param_static_gain_sz,		// 21
	param_lfx_gain,				// 22
	param_lfx_gain_sz,			// 23
	param_pilot_gain,			// 24
	param_pilot_gain_sz,		// 25
	param_wirte_flag,			// 26
	param_wirte_flag_sz,		// 27
	param_max,
};

static int param_dsm[param_max];
static void set_dsm_onoff_status(int onoff);

extern int32_t dsm_open(int32_t port_id,uint32_t*  dsm_params, u8* param);
extern int get_dsm_onoff_status(void);
#endif /* USE_DSM_MISC_DEV */

#ifdef USE_DSM_LOG
static void dsm_dump_func(int onoff);
static uint32_t exSeqCountTemp=0;
static uint32_t exSeqCountExcur=0;
static uint32_t newLogAvail=0;
#endif

static DEFINE_MUTEX(dsm_lock);

static const u8 max98504_reg_def[MAX98504_REG_CNT] = {
	[MAX98504_REG_01_INTERRUPT_STATUS] = 0,
	[MAX98504_REG_02_INTERRUPT_FLAGS] = 0,
	[MAX98504_REG_03_INTERRUPT_ENABLES] = 0,
	[MAX98504_REG_04_INTERRUPT_FLAG_CLEARS] = 0,
	[MAX98504_REG_10_GPIO_ENABLE] = 0,
	[MAX98504_REG_11_GPIO_CONFIG] = 0,
	[MAX98504_REG_12_WATCHDOG_ENABLE] = 0,
	[MAX98504_REG_13_WATCHDOG_CONFIG] = 0,
	[MAX98504_REG_14_WATCHDOG_CLEAR] = 0,
	[MAX98504_REG_15_CLOCK_MONITOR_ENABLE] = 0,
	[MAX98504_REG_16_PVDD_BROWNOUT_ENABLE] = 0,
	[MAX98504_REG_17_PVDD_BROWNOUT_CONFIG_1] = 0,
	[MAX98504_REG_18_PVDD_BROWNOUT_CONFIG_2] = 0,
	[MAX98504_REG_19_PVDD_BROWNOUT_CONFIG_3] = 0,
	[MAX98504_REG_1A_PVDD_BROWNOUT_CONFIG_4] = 0,
	[MAX98504_REG_20_PCM_RX_ENABLES] = 0,
	[MAX98504_REG_21_PCM_TX_ENABLES] = 0,
	[MAX98504_REG_22_PCM_TX_HIZ_CONTROL] = 0,
	[MAX98504_REG_23_PCM_TX_CHANNEL_SOURCES] = 0,
	[MAX98504_REG_24_PCM_MODE_CONFIG] = 0,
	[MAX98504_REG_25_PCM_DSP_CONFIG] = 0,
	[MAX98504_REG_26_PCM_CLOCK_SETUP] = 0,
	[MAX98504_REG_27_PCM_SAMPLE_RATE_SETUP] = 0,
	[MAX98504_REG_28_PCM_TO_SPEAKER_MONOMIX] = 0,
	[MAX98504_REG_30_PDM_TX_ENABLES] = 0,
	[MAX98504_REG_31_PDM_TX_HIZ_CONTROL] = 0,
	[MAX98504_REG_32_PDM_TX_CONTROL] = 0,
	[MAX98504_REG_33_PDM_RX_ENABLE] = 0,
	[MAX98504_REG_34_SPEAKER_ENABLE] = 0,
	[MAX98504_REG_35_SPEAKER_SOURCE_SELECT] = 0,
	[MAX98504_REG_36_MEASUREMENT_ENABLES] = 0,
	[MAX98504_REG_37_ANALOGUE_INPUT_GAIN] = 0,
	[MAX98504_REG_38_TEMPERATURE_LIMIT_CONFIG] = 0,
	[MAX98504_REG_39_ANALOGUE_SPARE] = 0,
	[MAX98504_REG_40_GLOBAL_ENABLE] = 0,
	[MAX98504_REG_41_SOFTWARE_RESET] = 0,
};

static struct {
	u8 read;
	u8 write;
	u8 vol;
} max98504_reg_access[MAX98504_REG_CNT] = {
	[MAX98504_REG_01_INTERRUPT_STATUS] = { 0xFF, 0x00, 0xFF },
	[MAX98504_REG_02_INTERRUPT_FLAGS] = { 0xFF, 0x00, 0xFF },
	[MAX98504_REG_03_INTERRUPT_ENABLES] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_04_INTERRUPT_FLAG_CLEARS] = { 0x00, 0xFF, 0xFF },
	[MAX98504_REG_10_GPIO_ENABLE] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_11_GPIO_CONFIG] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_12_WATCHDOG_ENABLE] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_13_WATCHDOG_CONFIG] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_14_WATCHDOG_CLEAR] = { 0x00, 0xFF, 0xFF },
	[MAX98504_REG_15_CLOCK_MONITOR_ENABLE] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_16_PVDD_BROWNOUT_ENABLE] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_17_PVDD_BROWNOUT_CONFIG_1] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_18_PVDD_BROWNOUT_CONFIG_2] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_19_PVDD_BROWNOUT_CONFIG_3] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_1A_PVDD_BROWNOUT_CONFIG_4] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_20_PCM_RX_ENABLES] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_21_PCM_TX_ENABLES] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_22_PCM_TX_HIZ_CONTROL] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_23_PCM_TX_CHANNEL_SOURCES] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_24_PCM_MODE_CONFIG] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_25_PCM_DSP_CONFIG] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_26_PCM_CLOCK_SETUP] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_27_PCM_SAMPLE_RATE_SETUP] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_28_PCM_TO_SPEAKER_MONOMIX] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_30_PDM_TX_ENABLES] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_31_PDM_TX_HIZ_CONTROL] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_32_PDM_TX_CONTROL] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_33_PDM_RX_ENABLE] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_34_SPEAKER_ENABLE] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_35_SPEAKER_SOURCE_SELECT] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_36_MEASUREMENT_ENABLES] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_37_ANALOGUE_INPUT_GAIN] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_38_TEMPERATURE_LIMIT_CONFIG] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_39_ANALOGUE_SPARE] = { 0xFF, 0xFF, 0x00 },
	[MAX98504_REG_40_GLOBAL_ENABLE] = { 0xFF, 0xFF, 0xFF },
	[MAX98504_REG_41_SOFTWARE_RESET] = { 0x00, 0xFF, 0xFF },
};

static int max98504_volatile_register(struct snd_soc_codec *codec, unsigned int reg)
{
	if (max98504_reg_access[reg].vol) {
		return 1;
	}
	else {
		/* Mark all volatile for 2nd Ev Kit i2c master */
		return 0;
	}
}

static int max98504_readable(struct snd_soc_codec *codec, unsigned int reg)
{
	if (reg >= MAX98504_REG_CNT) {
		return 0;
	}

	return max98504_reg_access[reg].read != 0;
}

static int max98504_reset(struct snd_soc_codec *codec)
{
	int ret;
	msg_maxim("\n");

	/* Reset the codec by writing to this write-only reset register */
	ret = snd_soc_write(codec, MAX98504_REG_41_SOFTWARE_RESET, M98504_SOFTWARE_RESET_MASK);
	if (ret < 0) {
		dev_err(codec->dev, "Failed to reset codec: %d\n", ret);
		return ret;
	}

	msleep(10);

	return ret;
}

static int max98504_rxpcm_gain_set(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_kcontrol_chip(kcontrol);
	unsigned int sel = ucontrol->value.integer.value[0];

	msg_maxim("val=%d\n",sel);

	snd_soc_update_bits(codec, MAX98504_REG_25_PCM_DSP_CONFIG,
	    M98504_PCM_DSP_CFG_RX_GAIN_MASK,
		sel << M98504_PCM_DSP_CFG_RX_GAIN_SHIFT);

	return 0;
}

static int max98504_rxpcm_gain_get(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_kcontrol_chip(kcontrol);
	unsigned int val = snd_soc_read(codec, MAX98504_REG_25_PCM_DSP_CONFIG);

	val = (val & M98504_PCM_DSP_CFG_RX_GAIN_MASK) >> M98504_PCM_DSP_CFG_RX_GAIN_SHIFT;

	ucontrol->value.integer.value[0] = val;
	msg_maxim("val=%d\n",val);

	return 0;
}

static int max98504_ain_gain_set(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_kcontrol_chip(kcontrol);
	unsigned int sel = ucontrol->value.integer.value[0];

	msg_maxim("val=%d\n",sel);

	snd_soc_update_bits(codec, MAX98504_REG_37_ANALOGUE_INPUT_GAIN,
						M98504_ANALOG_INPUT_GAIN_MASK,
						sel << M98504_ANALOG_INPUT_GAIN_SHIFT);

	return 0;
}

#ifdef USE_DSM_MISC_DEV
static int max98504_dsm_status_get(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	ucontrol->value.integer.value[0] = get_dsm_onoff_status()>0?1:0;
	
	msg_maxim("dsm status =%d\n",get_dsm_onoff_status());

	return 0;
}

static int max98504_dsm_status_set(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	unsigned int sel = ucontrol->value.integer.value[0];

	set_dsm_onoff_status(sel>0?1:0);
	
	msg_maxim("val=%d\n",sel);

	return 0;
}
#endif

#ifdef USE_DSM_LOG
static int max98504_dsm_dump_get(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	ucontrol->value.integer.value[0] = (newLogAvail&0x3);

	msg_maxim("get status:%d\n", (int) ucontrol->value.integer.value[0]);

	newLogAvail &= 0x1;

	return 0;
}

static int max98504_dsm_dump_set(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	unsigned int sel = ucontrol->value.integer.value[0];

	dsm_dump_func(1);
	
	msg_maxim("set(sel:%d)\n", sel);

	return 0;
}
#endif

static int max98504_ain_gain_get(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_kcontrol_chip(kcontrol);
	unsigned int val = snd_soc_read(codec, MAX98504_REG_37_ANALOGUE_INPUT_GAIN);

	val = (val & M98504_ANALOG_INPUT_GAIN_MASK) >> M98504_ANALOG_INPUT_GAIN_SHIFT;

	ucontrol->value.integer.value[0] = val;
	msg_maxim("val=%d\n",val);

	return 0;
}

static const unsigned int max98504_rxpcm_gain_tlv[] = {
	TLV_DB_RANGE_HEAD(1),
	0, 12, TLV_DB_SCALE_ITEM(0, 100, 0),
};

static const unsigned int max98504_ain_gain_tlv[] = {
	TLV_DB_RANGE_HEAD(1),
	0, 1, TLV_DB_SCALE_ITEM(1200, 600, 0),
};

static const char * max98504_enableddisabled_text[] = {"Disabled", "Enabled"};

static const struct soc_enum max98504_ispken_enum =
	SOC_ENUM_SINGLE(MAX98504_REG_36_MEASUREMENT_ENABLES, M98504_MEAS_I_EN_MASK,
					ARRAY_SIZE(max98504_enableddisabled_text), max98504_enableddisabled_text);

static const struct soc_enum max98504_vspken_enum =
	SOC_ENUM_SINGLE(MAX98504_REG_36_MEASUREMENT_ENABLES, M98504_MEAS_V_EN_MASK,
					ARRAY_SIZE(max98504_enableddisabled_text), max98504_enableddisabled_text);

static const char * max98504_vbatbrown_code_text[] = { "2.6V", "2.65V","Reserved", "Reserved","Reserved","Reserved","Reserved","Reserved",\
														"Reserved","Reserved","Reserved","Reserved","Reserved","Reserved","Reserved","Reserved",\
														"Reserved","Reserved","Reserved","Reserved","Reserved","Reserved","Reserved","Reserved",\
														"Reserved","Reserved","Reserved","Reserved","Reserved","Reserved","Reserved","3.7V"};

static const struct soc_enum max98504_brownout_code_enum =
	SOC_ENUM_SINGLE(MAX98504_REG_17_PVDD_BROWNOUT_CONFIG_1, M98504_PVDD_BROWNOUT_CFG1_CODE_SHIFT, 31, max98504_vbatbrown_code_text);

static const char * max98504_vbatbrown_max_atten_text[] = {"0dB","1dB","2dB","3dB","4dB","5dB","6dB"};

static const struct soc_enum max98504_brownout_max_atten_enum =
	SOC_ENUM_SINGLE(MAX98504_REG_17_PVDD_BROWNOUT_CONFIG_1, M98504_PVDD_BROWNOUT_CFG1_MAX_ATTEN_SHIFT, 6, max98504_vbatbrown_max_atten_text);

static const char * max98504_flt_mode_text[] = {"Voice", "Music"};

static const struct soc_enum max98504_pcm_rx_flt_mode_enum =
	SOC_ENUM_SINGLE(MAX98504_REG_25_PCM_DSP_CONFIG, M98504_PCM_DSP_CFG_RX_FLT_MODE_SHIFT, 1, max98504_flt_mode_text);

static const char * max98504_pcm_bsel_text[] = {"Reserved","Reserved","32","48", "64", "Reserved", "128", "Reserved", "256"};

static const struct soc_enum max98504_pcm_bsel_enum =
	SOC_ENUM_SINGLE(MAX98504_REG_26_PCM_CLOCK_SETUP, M98504_PCM_CLK_SETUP_BSEL_SHIFT, 8, max98504_pcm_bsel_text);

static const struct snd_kcontrol_new max98504_snd_controls[] = {
	SOC_SINGLE("GPIO Pin Switch", MAX98504_REG_10_GPIO_ENABLE, M98504_GPIO_ENALBE_SHIFT, 1, 0),
	SOC_SINGLE("Watchdog Enable Switch", MAX98504_REG_12_WATCHDOG_ENABLE, M98504_WDOG_ENABLE_SHIFT, 1, 0),
	SOC_SINGLE("Watchdog Config Switch", MAX98504_REG_13_WATCHDOG_CONFIG, M98504_WDOG_CONFIG_SHIFT, 3, 0),
	SOC_SINGLE("Watchdog Clear Switch", MAX98504_REG_14_WATCHDOG_CLEAR, M98504_WDOG_CLEAR_SHIFT, 0xe9, 0),
	SOC_SINGLE("Clock Monitor Switch", MAX98504_REG_15_CLOCK_MONITOR_ENABLE, M98504_CMON_ENA_SHIFT, 1, 0),
	SOC_SINGLE("Brownout Protection Switch", MAX98504_REG_16_PVDD_BROWNOUT_ENABLE, M98504_CMON_ENA_SHIFT, 1, 0),
	SOC_ENUM("Brownout Threshold", max98504_brownout_code_enum),
	SOC_ENUM("Brownout Attenuation Value", max98504_brownout_max_atten_enum),
	SOC_SINGLE("Brownout Attack Hold Time", MAX98504_REG_18_PVDD_BROWNOUT_CONFIG_2, M98504_PVDD_BROWNOUT_CFG2_ATTK_HOLD_SHIFT, 255, 0),
	SOC_SINGLE("Brownout Timed Hold", MAX98504_REG_19_PVDD_BROWNOUT_CONFIG_3, M98504_PVDD_BROWNOUT_CFG3_TIMED_HOLD_SHIFT, 255, 0),
	SOC_SINGLE("Brownout Release", MAX98504_REG_1A_PVDD_BROWNOUT_CONFIG_4, M98504_PVDD_BROWNOUT_CFG4_RELEASE_SHIFT, 255, 0),

	SOC_SINGLE("PCM BCLK Edge", MAX98504_REG_24_PCM_MODE_CONFIG, M98504_PCM_MODE_CFG_BCLKEDGE_SHIFT, 1, 0),
	SOC_SINGLE("PCM Channel Select", MAX98504_REG_24_PCM_MODE_CONFIG, M98504_PCM_MODE_CFG_CHSEL_SHIFT, 1, 0),
	SOC_SINGLE("PCM Transmit Extra HiZ Switch", MAX98504_REG_24_PCM_MODE_CONFIG, M98504_PCM_MODE_CFG_TX_EXTRA_HIZ_SHIFT, 1, 0),
	SOC_SINGLE("PCM Output Dither Switch", MAX98504_REG_25_PCM_DSP_CONFIG, M98504_PCM_DSP_CFG_TX_DITH_EN_SHIFT, 1, 0),
	SOC_SINGLE("PCM Measurement DC Blocking Filter Switch", MAX98504_REG_25_PCM_DSP_CONFIG, M98504_PCM_DSP_CFG_MEAS_DCBLK_EN_SHIFT, 1, 0),
	SOC_SINGLE("PCM Input Dither Switch", MAX98504_REG_25_PCM_DSP_CONFIG, M98504_PCM_DSP_CFG_RX_DITH_EN_SHIFT, 1, 0),
	SOC_ENUM("PCM Output Filter Mode", max98504_pcm_rx_flt_mode_enum),
	SOC_SINGLE_EXT_TLV("PCM Rx Gain",
						MAX98504_REG_25_PCM_DSP_CONFIG, M98504_PCM_DSP_CFG_RX_GAIN_SHIFT,
						M98504_PCM_DSP_CFG_RX_GAIN_WIDTH - 1, 1, max98504_rxpcm_gain_get, max98504_rxpcm_gain_set, 
						max98504_rxpcm_gain_tlv),

	SOC_SINGLE("DAC MONOMIX", MAX98504_REG_28_PCM_TO_SPEAKER_MONOMIX,
				M98504_PCM_TO_SPK_MONOMIX_CFG_SHIFT, 3, 0),

	SOC_ENUM("PCM BCLK rate", max98504_pcm_bsel_enum),
	
	SOC_ENUM("Speaker Current Sense Enable", max98504_ispken_enum),
	SOC_ENUM("Speaker Voltage Sense Enable", max98504_vspken_enum),

	SOC_SINGLE_EXT_TLV("AIN Gain",
						MAX98504_REG_37_ANALOGUE_INPUT_GAIN, M98504_ANALOG_INPUT_GAIN_SHIFT,
						M98504_ANALOG_INPUT_GAIN_WIDTH - 1, 1, max98504_ain_gain_get, max98504_ain_gain_set, 
						max98504_ain_gain_tlv),

	SOC_SINGLE("AUTH_STATUS", MAX98504_REG_01_INTERRUPT_STATUS, 0, M98504_INT_INTERRUPT_STATUS_MASK, 0),

#ifdef USE_DSM_MISC_DEV
	SOC_SINGLE_EXT("Dynamic Speaker Management", SND_SOC_NOPM, 0, 1, 0,
					max98504_dsm_status_get, max98504_dsm_status_set),
#endif
#ifdef USE_DSM_LOG
	SOC_SINGLE_EXT("DSM LOG", SND_SOC_NOPM, 0, 3, 0,
					max98504_dsm_dump_get, max98504_dsm_dump_set),
#endif
};

static const char *spk_src_mux_text[] = { "PCM", "AIN", "PDM_CH0", "PDM_CH1" };

static const struct soc_enum spk_src_mux_enum =
	SOC_ENUM_SINGLE(MAX98504_REG_35_SPEAKER_SOURCE_SELECT, M98504_SPK_SRC_SEL_SHIFT,
					ARRAY_SIZE(spk_src_mux_text), spk_src_mux_text);
static const struct snd_kcontrol_new max98504_spk_src_mux =
	SOC_DAPM_ENUM("SPK_SRC Mux", spk_src_mux_enum);

static const struct snd_kcontrol_new max98504_digital_mono_mixer_controls[] = {
	SOC_DAPM_SINGLE("CH0 DAC Switch", MAX98504_REG_28_PCM_TO_SPEAKER_MONOMIX,
					M98504_PCM_TO_SPK_MONOMIX_CH0_SRC_SHIFT, 1, 0),
	SOC_DAPM_SINGLE("CH1 DAC Switch", MAX98504_REG_28_PCM_TO_SPEAKER_MONOMIX,
					M98504_PCM_TO_SPK_MONOMIX_CH1_SRC_SHIFT, 1, 0),
};

static const struct snd_soc_dapm_widget max98504_dapm_widgets[] = {
#ifndef USE_SHDN_BY_ALSA_UCM	
	SND_SOC_DAPM_SUPPLY("SHDN", MAX98504_REG_40_GLOBAL_ENABLE, M98504_GLOBAL_EN_SHIFT, 0, NULL, 0),
#endif
	SND_SOC_DAPM_INPUT("Voltage Data"),
	SND_SOC_DAPM_INPUT("Current Data"),
	SND_SOC_DAPM_INPUT("Analog Input"),

	SND_SOC_DAPM_ADC("ADCL", NULL, MAX98504_REG_36_MEASUREMENT_ENABLES,
					M98504_MEAS_V_EN_SHIFT, 0),
	SND_SOC_DAPM_ADC("ADCR", NULL, MAX98504_REG_36_MEASUREMENT_ENABLES,
					M98504_MEAS_I_EN_SHIFT, 0),

	SND_SOC_DAPM_AIF_OUT("AIFOUTL", "AIF1 Capture", 0, SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_OUT("AIFOUTR", "AIF1 Capture", 1, SND_SOC_NOPM, 0, 0),

	SND_SOC_DAPM_AIF_IN("AIFINL", "AIF1 Playback", 0, SND_SOC_NOPM, 0, 0),
	SND_SOC_DAPM_AIF_IN("AIFINR", "AIF1 Playback", 1, SND_SOC_NOPM, 0, 0),

	SND_SOC_DAPM_DAC("DACL", NULL, MAX98504_REG_20_PCM_RX_ENABLES,
					M98504_PCM_RX_EN_CH0_SHIFT, 0),
	SND_SOC_DAPM_DAC("DACR", NULL, MAX98504_REG_20_PCM_RX_ENABLES,
					M98504_PCM_RX_EN_CH1_SHIFT, 0),

	SND_SOC_DAPM_MIXER("Digital Mono Mixer", SND_SOC_NOPM, 0, 0,
						&max98504_digital_mono_mixer_controls[0],
						ARRAY_SIZE(max98504_digital_mono_mixer_controls)),

	SND_SOC_DAPM_MUX("SPK_SRC Mux", SND_SOC_NOPM, 0, 0, &max98504_spk_src_mux),

	SND_SOC_DAPM_PGA("SHDN_TEMP", MAX98504_REG_40_GLOBAL_ENABLE, M98504_GLOBAL_EN_SHIFT, 0, NULL, 0),
	SND_SOC_DAPM_PGA("SPK Mono Out", MAX98504_REG_34_SPEAKER_ENABLE, M98504_SPK_EN_SHIFT, 0, NULL, 0),
	SND_SOC_DAPM_OUTPUT("SPKOUT"),
};

static const struct snd_soc_dapm_route max98504_audio_map[] = {
	{"ADCL", NULL, "Voltage Data"},
	{"ADCR", NULL, "Current Data"},

	{"AIFOUTL", NULL, "ADCL"},
	{"AIFOUTR", NULL, "ADCR"},
#ifndef USE_SHDN_BY_ALSA_UCM
	{"AIFOUTL", NULL, "SHDN"},
	{"AIFOUTR", NULL, "SHDN"},
	{"AIFINL", NULL, "SHDN"},
	{"AIFINR", NULL, "SHDN"},
#endif
	{"Digital Mono Mixer", "CH0 DAC Switch", "DACL"}, 
	{"Digital Mono Mixer", "CH1 DAC Switch", "DACR"},

	{"SPK_SRC Mux", "PCM", "Digital Mono Mixer"}, 
	{"SPK_SRC Mux", "AIN", "Analog Input"}, 
	{"SHDN_TEMP", NULL, "SPK_SRC Mux"},

	{"SPK Mono Out", NULL, "SHDN_TEMP"}, 
	{"SPKOUT", NULL, "SPK Mono Out"}, 
};

static int max98504_add_widgets(struct snd_soc_codec *codec)
{
	msg_maxim("\n");

	snd_soc_add_codec_controls(codec, max98504_snd_controls,
								ARRAY_SIZE(max98504_snd_controls));

	return 0;
}

/* codec sample rate config parameter table */
static const struct { 
	u32 rate;
	u8  sr;
} rate_table[] = {
	{8000,  (0)},
	{11025,	(1)},
	{12000, (2)},
	{16000, (3)},
	{22050, (4)},
	{24000, (5)},
    {32000, (6)},
	{44100, (7)},
	{48000, (8)},
};

static inline int rate_value(int rate, u8 *value)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(rate_table); i++) {
       if (rate_table[i].rate >= rate) {
               *value = rate_table[i].sr;
               return 0;
       }
	}

	*value = rate_table[0].sr;

	return -EINVAL;
}

/* #define TDM */
static int max98504_set_tdm_slot(struct snd_soc_dai *codec_dai, unsigned int tx_mask,
				      unsigned int rx_mask, int slots, int slot_width)
{
	return 0;
}

static int max98504_dai_set_fmt(struct snd_soc_dai *codec_dai, unsigned int fmt)
{
	struct snd_soc_codec *codec = codec_dai->codec;
	struct max98504_priv *max98504 = snd_soc_codec_get_drvdata(codec);
	struct max98504_cdata *cdata;
	u8 regval;

	msg_maxim("\n");

	cdata = &max98504->dai[0];

	if (fmt != cdata->fmt) {
		cdata->fmt = fmt;

		regval = 0;

		switch (fmt & SND_SOC_DAIFMT_MASTER_MASK) {
			case SND_SOC_DAIFMT_CBS_CFS:
			case SND_SOC_DAIFMT_CBM_CFM:
				break;
			case SND_SOC_DAIFMT_CBS_CFM:
			case SND_SOC_DAIFMT_CBM_CFS:
			default:
				dev_err(codec->dev, "DAI clock mode unsupported");
				return -EINVAL;
		}

		switch (fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
			case SND_SOC_DAIFMT_I2S:
				snd_soc_update_bits(codec, MAX98504_REG_24_PCM_MODE_CONFIG,
					M98504_PCM_MODE_CFG_FORMAT_MASK, M98504_PCM_MODE_CFG_FORMAT_I2S_MASK);
				break;
			case SND_SOC_DAIFMT_LEFT_J:
				snd_soc_update_bits(codec, MAX98504_REG_24_PCM_MODE_CONFIG,
					M98504_PCM_MODE_CFG_FORMAT_MASK, M98504_PCM_MODE_CFG_FORMAT_LJ_MASK);
				break;
			case SND_SOC_DAIFMT_RIGHT_J:
				snd_soc_update_bits(codec, MAX98504_REG_24_PCM_MODE_CONFIG,
					M98504_PCM_MODE_CFG_FORMAT_MASK, M98504_PCM_MODE_CFG_FORMAT_RJ_MASK);
				break;
			case SND_SOC_DAIFMT_DSP_A:
				/* Not supported mode */
			default:
				dev_err(codec->dev, "DAI format unsupported, fmt:0x%d", fmt);
				return -EINVAL;
		}

		switch (fmt & SND_SOC_DAIFMT_INV_MASK) {
			case SND_SOC_DAIFMT_NB_NF:
			case SND_SOC_DAIFMT_NB_IF:
				break;
			case SND_SOC_DAIFMT_IB_NF:
			case SND_SOC_DAIFMT_IB_IF:
				break;
			default:
				dev_err(codec->dev, "DAI invert mode unsupported");
				return -EINVAL;
		}

		snd_soc_write(codec, MAX98504_REG_26_PCM_CLOCK_SETUP, 0);
	}

	return 0;
}

static int max98504_set_bias_level(struct snd_soc_codec *codec,
				   enum snd_soc_bias_level level)
{
	int ret;

	msg_maxim("level=%d \n", level);

	switch (level) {
		case SND_SOC_BIAS_ON:
			if (codec->dapm.bias_level == SND_SOC_BIAS_OFF) {
				ret = snd_soc_cache_sync(codec);

				if (ret != 0) {
					dev_err(codec->dev, "Failed to sync cache: %d\n", ret);
					return ret;
				}
			}
			snd_soc_update_bits(codec, MAX98504_REG_40_GLOBAL_ENABLE, M98504_GLOBAL_EN_MASK, M98504_GLOBAL_EN_MASK);
		break;

		case SND_SOC_BIAS_PREPARE:
			break;

		case SND_SOC_BIAS_STANDBY:
		case SND_SOC_BIAS_OFF:
			snd_soc_update_bits(codec, MAX98504_REG_40_GLOBAL_ENABLE,	M98504_GLOBAL_EN_MASK, 0x00);
			codec->cache_sync = 1;
			break;
	}

	codec->dapm.bias_level = level;

	return 0;
}

static int max98504_dai_hw_params(struct snd_pcm_substream *substream,
				   struct snd_pcm_hw_params *params,
				   struct snd_soc_dai *dai)
{
	struct snd_soc_codec *codec = dai->codec;
	struct max98504_priv *max98504 = snd_soc_codec_get_drvdata(codec);
	struct max98504_cdata *cdata;

	unsigned int rate;
	u8 regval;

	msg_maxim("\n");

	cdata = &max98504->dai[0];

	rate = params_rate(params);

	switch (params_format(params)) {
		case SNDRV_PCM_FORMAT_S8:
			snd_soc_update_bits(codec, MAX98504_REG_24_PCM_MODE_CONFIG,
				M98504_PCM_MODE_CFG_CH_SIZE_MASK, M98504_PCM_MODE_CFG_CH_SIZE_8_MASK);
			break;
		case SNDRV_PCM_FORMAT_S16_LE:
			snd_soc_update_bits(codec, MAX98504_REG_24_PCM_MODE_CONFIG,
				M98504_PCM_MODE_CFG_CH_SIZE_MASK, M98504_PCM_MODE_CFG_CH_SIZE_16_MASK);
			break;
		case SNDRV_PCM_FORMAT_S24_LE:
			snd_soc_update_bits(codec, MAX98504_REG_24_PCM_MODE_CONFIG,
				M98504_PCM_MODE_CFG_CH_SIZE_MASK, M98504_PCM_MODE_CFG_CH_SIZE_24_MASK);
			break;
		case SNDRV_PCM_FORMAT_S32_LE:
			snd_soc_update_bits(codec, MAX98504_REG_24_PCM_MODE_CONFIG,
				M98504_PCM_MODE_CFG_CH_SIZE_MASK, M98504_PCM_MODE_CFG_CH_SIZE_32_MASK);
			break;
		default:
			return -EINVAL;
	}

	if (rate_value(rate, &regval))
		return -EINVAL;

	/* Update sample rate mode */
	snd_soc_update_bits(codec, MAX98504_REG_27_PCM_SAMPLE_RATE_SETUP,
		M98504_PCM_SR_SETUP_SPK_SR_MASK, regval<<M98504_PCM_SR_SETUP_SPK_SR_SHIFT);	

	snd_soc_update_bits(codec, MAX98504_REG_27_PCM_SAMPLE_RATE_SETUP,
		M98504_PCM_SR_SETUP_MEAS_SR_MASK, regval<<M98504_PCM_SR_SETUP_MEAS_SR_SHIFT);

	return 0;
}

/*
 * PLL / Sysclk
 */
static int max98504_dai_set_sysclk(struct snd_soc_dai *dai,
				   int clk_id, unsigned int freq, int dir)
{
	struct snd_soc_codec *codec = dai->codec;
	struct max98504_priv *max98504 = snd_soc_codec_get_drvdata(codec);

	msg_maxim("clk_id;%d, freq:%d, dir:%d\n", clk_id, freq, dir);

	/* Requested clock frequency is already setup */
	if (freq == max98504->sysclk)
		return 0;

	max98504->sysclk = freq;

	return 0;
}

static int max98504_dai_digital_mute(struct snd_soc_dai *codec_dai, int mute)
{
	//struct snd_soc_codec *codec = codec_dai->codec;

	msg_maxim("- mute:%d\n", mute);

	if(mute) {
		#ifdef MAX98504_WATCHDOG_ENABLE
		snd_soc_write(codec, MAX98504_REG_12_WATCHDOG_ENABLE, 0);
		#endif
		//snd_soc_update_bits(codec, MAX98504_REG_34_SPEAKER_ENABLE, M98504_SPK_EN_MASK, 0);
	}
	else {
		#ifdef MAX98504_WATCHDOG_ENABLE
		snd_soc_write(codec, MAX98504_REG_12_WATCHDOG_ENABLE, M98504_WDOG_ENABLE_MASK);
		#endif
		//snd_soc_update_bits(codec, MAX98504_REG_34_SPEAKER_ENABLE, M98504_SPK_EN_MASK, M98504_SPK_EN_MASK);
	}
	return 0;
}

#define MAX98504_RATES SNDRV_PCM_RATE_8000_48000
#define MAX98504_FORMATS (SNDRV_PCM_FMTBIT_S8 | SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S24_LE | SNDRV_PCM_FMTBIT_S32_LE)

static struct snd_soc_dai_ops max98504_dai_ops = {
	.set_sysclk = max98504_dai_set_sysclk,
	.set_fmt = max98504_dai_set_fmt,
	.set_tdm_slot = max98504_set_tdm_slot,
	.hw_params = max98504_dai_hw_params,
	.digital_mute = max98504_dai_digital_mute,
};

static struct snd_soc_dai_driver max98504_dai[] = {
	{
		.name = "max98504-aif1",
		.playback = {
			.stream_name = "AIF1 Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = MAX98504_RATES,
			.formats = MAX98504_FORMATS,
		},
		.capture = {
			.stream_name = "AIF1 Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = MAX98504_RATES,
			.formats = MAX98504_FORMATS,
		},
		 .ops = &max98504_dai_ops,
	}
};

#if 1	// platform data.
static struct max98504_dsp_cfg dsp_cfg[] = {
	{
		.name = "FILTER",
		.tx_dither_en = 1,
		.rx_dither_en = 1,
		.meas_dc_block_en = 1,	
		.rx_flt_mode = 1,
	},
};

static struct max98504_pdata max98504_config = {
	.dsp_cfg = dsp_cfg,
	.clk_monitor_en = 0,
	.rx_ch_en = 0x00,
	.tx_ch_en = 0x03,
	.tx_hiz_ch_en = 0x00,
	.tx_ch_src = 0x2,
	.auth_en = 0,
	.wdog_time_out = 3,
};
#endif

static void max98504_handle_pdata(struct snd_soc_codec *codec)
{
	struct max98504_priv *max98504 = snd_soc_codec_get_drvdata(codec);
	struct max98504_pdata *pdata = max98504->pdata;

	struct max98504_dsp_cfg *dsp_cfg;
	u8 cmon_en, rx_en, tx_en, tx_hiz_en, tx_ch_src, auth_en, wdog_time_out;
	u8 regval;

	pdata = &max98504_config;

	msg_maxim("\n");

	if (!pdata) {
		dev_dbg(codec->dev, "No platform data\n");
		return;
	}

	dsp_cfg = pdata->dsp_cfg;
	cmon_en = pdata->clk_monitor_en;
	rx_en = pdata->rx_ch_en;
	tx_en = pdata->tx_ch_en;
	tx_hiz_en = pdata->tx_hiz_ch_en;
	tx_ch_src = pdata->tx_ch_src;
	auth_en = pdata->auth_en;
	wdog_time_out = pdata->wdog_time_out;

	/* filter */
	if(dsp_cfg->tx_dither_en)	regval = M98504_PCM_DSP_CFG_TX_DITH_EN_MASK;
	if(dsp_cfg->meas_dc_block_en)	regval |= M98504_PCM_DSP_CFG_MEAS_DCBLK_EN_MASK;
	if(dsp_cfg->rx_dither_en)	regval |= M98504_PCM_DSP_CFG_RX_DITH_EN_MASK;
	if(dsp_cfg->rx_flt_mode)	regval |= M98504_PCM_DSP_CFG_RX_FLT_MODE_MASK;

	snd_soc_update_bits(codec, MAX98504_REG_25_PCM_DSP_CONFIG,
		M98504_PCM_DSP_CFG_FLT_MASK, regval);

	snd_soc_write(codec, MAX98504_REG_15_CLOCK_MONITOR_ENABLE, cmon_en & M98504_CMON_ENA_MASK);

	snd_soc_write(codec, MAX98504_REG_20_PCM_RX_ENABLES, rx_en);
	snd_soc_write(codec, MAX98504_REG_21_PCM_TX_ENABLES, tx_en);
	snd_soc_write(codec, MAX98504_REG_22_PCM_TX_HIZ_CONTROL, tx_hiz_en);
	snd_soc_write(codec, MAX98504_REG_23_PCM_TX_CHANNEL_SOURCES, tx_ch_src);

	snd_soc_write(codec, MAX98504_REG_13_WATCHDOG_CONFIG, wdog_time_out);

	msg_maxim("RX_EN:0x%d, TX_EN:0x%d, TX_SRC:0x%d, wdog_time_out:%d\n", rx_en, tx_en, tx_ch_src, wdog_time_out);
}

static int max98504_suspend(struct snd_soc_codec *codec)
{
	msg_maxim("\n");

	return 0;
}

static int max98504_resume(struct snd_soc_codec *codec)
{
	msg_maxim("\n");

	return 0;
}

#ifdef MAX98504_WATCHDOG_ENABLE
static irqreturn_t max98504_interrupt(int irq, void *data)
{
	struct snd_soc_codec *codec = (struct snd_soc_codec *) data;
	struct max98504_priv *max98504 = snd_soc_codec_get_drvdata(codec);

	unsigned int mask;
	unsigned int flag;

	mask = snd_soc_read(codec, MAX98504_REG_03_INTERRUPT_ENABLES);
	flag = snd_soc_read(codec, MAX98504_REG_02_INTERRUPT_FLAGS);

	msg_maxim("flag=0x%02x mask=0x%02x -> flag=0x%02x\n", flag, mask, flag & mask);

	flag &= mask;

	if (!flag)
		return IRQ_NONE;
	
	/* Send work to be scheduled */
	if (flag & M98504_INT_GENFAIL_EN_MASK) {
		msg_maxim("M98504_INT_GENFAIL_EN_MASK active!");
	}

	if (flag & M98504_INT_AUTHDONE_EN_MASK) {
		msg_maxim("M98504_INT_AUTHDONE_EN_MASK active!");
	}

	if (flag & M98504_INT_VBATBROWN_EN_MASK) {
		msg_maxim("M98504_INT_VBATBROWN_EN_MASK active!");
	}

	if (flag & M98504_INT_WATCHFAIL_EN_MASK) {
		msg_maxim("M98504_INT_WATCHFAIL_EN_MASK active!");
		schedule_delayed_work(&max98504->work, msecs_to_jiffies(2000));
	}

	if (flag & M98504_INT_THERMWARN_END_EN_MASK) {
		msg_maxim("M98504_INT_THERMWARN_END_EN_MASK active!");
	}

	if (flag & M98504_INT_THERMWARN_BGN_EN_MASK) {
		msg_maxim("M98504_INT_THERMWARN_BGN_EN_MASK active!\n");
	}

	if (flag & M98504_INT_THERMSHDN_END_EN_MASK) {
		msg_maxim("M98504_INT_THERMSHDN_END_EN_MASK active!\n");
	}

	if (flag & M98504_INT_THERMSHDN_BGN_FLAG_MASK) {
		msg_maxim("M98504_INT_THERMSHDN_BGN_FLAG_MASK active!\n");
	}

	snd_soc_write(codec, MAX98504_REG_04_INTERRUPT_FLAG_CLEARS, flag&0xff);

	return IRQ_HANDLED;
}
#endif

#ifdef MAX98504_WATCHDOG_ENABLE
static void max98504_work(struct work_struct *work)
{
	struct max98504_priv *max98504 = container_of(work, struct max98504_priv, work.work);
	struct snd_soc_codec *codec= max98504->codec;

	if(codec->dapm.bias_level==SND_SOC_BIAS_ON)	{
		snd_soc_write(codec, MAX98504_REG_14_WATCHDOG_CLEAR, 0xE9);
		snd_soc_write(codec, MAX98504_REG_40_GLOBAL_ENABLE, M98504_GLOBAL_EN_MASK);
		msg_maxim("Watchdog Recovery\n");
	}
	else {
		msg_maxim("No Watchdog Recovery.\n");
	}
}
#endif

#ifdef USE_DSM_LOG
#define LOG_BUFFER_ARRAY_SIZE 10
#define BEFORE_BUFSIZE 4+(LOG_BUFFER_ARRAY_SIZE*2)	// 4 byte allignment
#define AFTER_BUFSIZE LOG_BUFFER_ARRAY_SIZE*4		// 4 byte allignment

static DEFINE_MUTEX(max98504_dsm_log_lock);
static bool max98504_dsm_log_present = false;
static struct tm max98504_dsm_log_timestamp;
static uint8_t max98504_dsm_byteLogArray[BEFORE_BUFSIZE];
static uint32_t max98504_dsm_intLogArray[BEFORE_BUFSIZE];
static uint8_t max98504_dsm_afterProbByteLogArray[AFTER_BUFSIZE];
static uint32_t max98504_dsm_afterProbIntLogArray[AFTER_BUFSIZE];

void max98504_dsm_log_update(const void *byteLogArray, const void *intLogArray, const void *afterProbByteLogArray, const void *afterProbIntLogArray)
{
	struct timeval tv;
	//uint32_t i, temp;
	mutex_lock(&max98504_dsm_log_lock);

	memcpy(max98504_dsm_byteLogArray, byteLogArray, sizeof(max98504_dsm_byteLogArray));
	memcpy(max98504_dsm_intLogArray, intLogArray, sizeof(max98504_dsm_intLogArray));

	memcpy(max98504_dsm_afterProbByteLogArray, afterProbByteLogArray, sizeof(max98504_dsm_afterProbByteLogArray));
	memcpy(max98504_dsm_afterProbIntLogArray, afterProbIntLogArray, sizeof(max98504_dsm_afterProbIntLogArray));

	do_gettimeofday(&tv);
	time_to_tm(tv.tv_sec, 0, &max98504_dsm_log_timestamp);  

	max98504_dsm_log_present = true;

	mutex_unlock(&max98504_dsm_log_lock);
}

static void max98504_dsm_log_free (void **byteLogArray, void **intLogArray, void **afterbyteLogArray, void **afterintLogArray)
{
	if (likely(*byteLogArray)) {
		kfree(*byteLogArray);
		*byteLogArray = NULL;
	}

	if (likely(*intLogArray)) {
		kfree(*intLogArray);
		*intLogArray = NULL;
	}

	if (likely(*afterbyteLogArray)) {
		kfree(*afterbyteLogArray);
		*afterbyteLogArray = NULL;
	}

	if (likely(*afterintLogArray)) {
		kfree(*afterintLogArray);
		*afterintLogArray = NULL;
	}
}

static int max98504_dsm_log_duplicate (void **byteLogArray, void **intLogArray, void **afterbyteLogArray, void **afterintLogArray)
{
	void *blog_buf = NULL, *ilog_buf = NULL, *after_blog_buf = NULL, *after_ilog_buf = NULL; 
	int rc = 0;

	mutex_lock(&max98504_dsm_log_lock);

	if (unlikely(!max98504_dsm_log_present)) {
		rc = -ENODATA;
		goto abort;
	}

	blog_buf = kzalloc(sizeof(max98504_dsm_byteLogArray), GFP_KERNEL);
	ilog_buf = kzalloc(sizeof(max98504_dsm_intLogArray), GFP_KERNEL);
	after_blog_buf = kzalloc(sizeof(max98504_dsm_afterProbByteLogArray), GFP_KERNEL);
	after_ilog_buf = kzalloc(sizeof(max98504_dsm_afterProbIntLogArray), GFP_KERNEL);

	if (unlikely(!blog_buf || !ilog_buf || !after_blog_buf || !after_ilog_buf)) {
		rc = -ENOMEM;
		goto abort;
	}

	memcpy(blog_buf, max98504_dsm_byteLogArray, sizeof(max98504_dsm_byteLogArray));
	memcpy(ilog_buf, max98504_dsm_intLogArray, sizeof(max98504_dsm_intLogArray));
	memcpy(after_blog_buf, max98504_dsm_afterProbByteLogArray, sizeof(max98504_dsm_afterProbByteLogArray));
	memcpy(after_ilog_buf, max98504_dsm_afterProbIntLogArray, sizeof(max98504_dsm_afterProbIntLogArray));

	goto out;

abort:
	max98504_dsm_log_free(&blog_buf, &ilog_buf, &after_blog_buf, &after_ilog_buf);
out:
	*byteLogArray = blog_buf;
	*intLogArray  = ilog_buf;	
	*afterbyteLogArray = after_blog_buf;
	*afterintLogArray  = after_ilog_buf;
	mutex_unlock(&max98504_dsm_log_lock);

	return rc;
}

static ssize_t max98504_dsm_log_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	uint8_t *byteLogArray = NULL;
	uint32_t *intLogArray = NULL;
	uint8_t *afterbyteLogArray = NULL;
	uint32_t *afterintLogArray = NULL;
	int rc = 0;

	uint8_t logAvailable;
	uint8_t versionID;
	uint8_t *coilTempLogArray;
	uint8_t *exCurLogArray;
	uint8_t *AftercoilTempLogArray;
	uint8_t *AfterexCurLogArray;
	uint8_t *ExcurAftercoilTempLogArray;
	uint8_t *ExcurAfterexCurLogArray;

    uint32_t seqCountTemp;
    uint32_t seqCountExcur; 
	uint32_t *rdcLogArray;
	uint32_t *freqLogArray;
	uint32_t *AfterrdcLogArray;
	uint32_t *AfterfreqLogArray;
	uint32_t *ExcurAfterrdcLogArray;
	uint32_t *ExcurAfterfreqLogArray;

	rc = max98504_dsm_log_duplicate((void**)&byteLogArray, (void**)&intLogArray, (void**)&afterbyteLogArray, (void**)&afterintLogArray);

	if (unlikely(rc)) {
		rc = snprintf(buf, PAGE_SIZE, "no log\n");
#ifdef USE_DSM_MISC_DEV
 		if(param_dsm[param_excur_limit]!=0 && param_dsm[param_thermal_limit]!=0)	{
			rc += snprintf(buf+rc, PAGE_SIZE,  "[Parameter Set] excursionlimit:0x%x, rdcroomtemp:0x%x, coilthermallimit:0x%x, releasetime:0x%x\n",
							param_dsm[param_excur_limit],
							param_dsm[param_voice_coil],
							param_dsm[param_thermal_limit],
							param_dsm[param_release_time]);
			rc += snprintf(buf+rc, PAGE_SIZE,  "[Parameter Set] staticgain:0x%x, lfxgain:0x%x, pilotgain:0x%x\n",
							param_dsm[param_static_gain],
							param_dsm[param_lfx_gain],
							param_dsm[param_pilot_gain]);
		}
#endif /* USE_DSM_MISC_DEV */

		goto out;
	}

	logAvailable     = byteLogArray[0];
	versionID        = byteLogArray[1];
	coilTempLogArray = &byteLogArray[2];
	exCurLogArray    = &byteLogArray[2+LOG_BUFFER_ARRAY_SIZE];

	seqCountTemp       = intLogArray[0];
	seqCountExcur   = intLogArray[1];
	rdcLogArray  = &intLogArray[2];
	freqLogArray = &intLogArray[2+LOG_BUFFER_ARRAY_SIZE];

	AftercoilTempLogArray = &afterbyteLogArray[0];
	AfterexCurLogArray = &afterbyteLogArray[LOG_BUFFER_ARRAY_SIZE];
	AfterrdcLogArray = &afterintLogArray[0];
	AfterfreqLogArray = &afterintLogArray[LOG_BUFFER_ARRAY_SIZE];

	ExcurAftercoilTempLogArray = &afterbyteLogArray[LOG_BUFFER_ARRAY_SIZE*2];
	ExcurAfterexCurLogArray = &afterbyteLogArray[LOG_BUFFER_ARRAY_SIZE*3];
	ExcurAfterrdcLogArray = &afterintLogArray[LOG_BUFFER_ARRAY_SIZE*2];
	ExcurAfterfreqLogArray = &afterintLogArray[LOG_BUFFER_ARRAY_SIZE*3];

	if(logAvailable>0 && (exSeqCountTemp!=seqCountTemp || exSeqCountExcur!=seqCountExcur))	{
		exSeqCountTemp = seqCountTemp;
		exSeqCountExcur = seqCountExcur;
		newLogAvail |= 0x2;
	}

	rc += snprintf(buf+rc, PAGE_SIZE, "DSM LogData saved at %4d-%02d-%02d %02d:%02d:%02d (UTC)\n",
		(int)(max98504_dsm_log_timestamp.tm_year + 1900), 
		(int)(max98504_dsm_log_timestamp.tm_mon + 1),
		(int)(max98504_dsm_log_timestamp.tm_mday), 
		(int)(max98504_dsm_log_timestamp.tm_hour),
		(int)(max98504_dsm_log_timestamp.tm_min), 
		(int)(max98504_dsm_log_timestamp.tm_sec));

	if ((logAvailable & 0x1) == 0x1) { // excursion limit exceeded.
		rc += snprintf(buf+rc, PAGE_SIZE, "*** Excursion Limit was exceeded.\n");
		rc += snprintf(buf+rc, PAGE_SIZE, "Seq:%d, logAvailable=%d, versionID:2.5.%d\n", seqCountExcur, logAvailable, versionID);
		rc += snprintf(buf+rc, PAGE_SIZE, "Temperature={ %d, %d, %d, %d, %d, %d, %d, %d, %d, %d }\n", 
						ExcurAftercoilTempLogArray[0], ExcurAftercoilTempLogArray[1], ExcurAftercoilTempLogArray[2], ExcurAftercoilTempLogArray[3], ExcurAftercoilTempLogArray[4],
						ExcurAftercoilTempLogArray[5], ExcurAftercoilTempLogArray[6], ExcurAftercoilTempLogArray[7], ExcurAftercoilTempLogArray[8], ExcurAftercoilTempLogArray[9]);
		rc += snprintf(buf+rc, PAGE_SIZE,  "Excursion={ %d, %d, %d, %d, %d, %d, %d, %d, %d, %d }\n", 
						ExcurAfterexCurLogArray[0], ExcurAfterexCurLogArray[1], ExcurAfterexCurLogArray[2], ExcurAfterexCurLogArray[3], ExcurAfterexCurLogArray[4],
						ExcurAfterexCurLogArray[5], ExcurAfterexCurLogArray[6], ExcurAfterexCurLogArray[7], ExcurAfterexCurLogArray[8], ExcurAfterexCurLogArray[9]);
		rc += snprintf(buf+rc, PAGE_SIZE,  "Rdc={ %d, %d, %d, %d, %d, %d, %d, %d, %d, %d }\n",  
						ExcurAfterrdcLogArray[0], ExcurAfterrdcLogArray[1], ExcurAfterrdcLogArray[2], ExcurAfterrdcLogArray[3], ExcurAfterrdcLogArray[4],
						ExcurAfterrdcLogArray[5], ExcurAfterrdcLogArray[6], ExcurAfterrdcLogArray[7], ExcurAfterrdcLogArray[8], ExcurAfterrdcLogArray[9]);
		rc += snprintf(buf+rc, PAGE_SIZE,  "Frequency={ %d, %d, %d, %d, %d, %d, %d, %d, %d, %d }\n",  
						ExcurAfterfreqLogArray[0], ExcurAfterfreqLogArray[1], ExcurAfterfreqLogArray[2], ExcurAfterfreqLogArray[3], ExcurAfterfreqLogArray[4],
						ExcurAfterfreqLogArray[5], ExcurAfterfreqLogArray[6], ExcurAfterfreqLogArray[7], ExcurAfterfreqLogArray[8], ExcurAfterfreqLogArray[9]);	}

	if ((logAvailable&0x2) == 0x2) { // temperature limit exceeded.
		rc += snprintf(buf+rc, PAGE_SIZE, "*** Temperature Limit was exceeded.\n");
		rc += snprintf(buf+rc, PAGE_SIZE, "Seq:%d, logAvailable=%d, versionID:2.5.%d\n", seqCountTemp, logAvailable, versionID);
		rc += snprintf(buf+rc, PAGE_SIZE, "Temperature={ %d, %d, %d, %d, %d, %d, %d, %d, %d, %d,\n",  
						coilTempLogArray[0], coilTempLogArray[1], coilTempLogArray[2], coilTempLogArray[3], coilTempLogArray[4],
						coilTempLogArray[5], coilTempLogArray[6], coilTempLogArray[7], coilTempLogArray[8], coilTempLogArray[9]);
		rc += snprintf(buf+rc, PAGE_SIZE, "              %d, %d, %d, %d, %d, %d, %d, %d, %d, %d }\n",  
						AftercoilTempLogArray[0], AftercoilTempLogArray[1], AftercoilTempLogArray[2], AftercoilTempLogArray[3], AftercoilTempLogArray[4],
						AftercoilTempLogArray[5], AftercoilTempLogArray[6], AftercoilTempLogArray[7], AftercoilTempLogArray[8], AftercoilTempLogArray[9]);
		rc += snprintf(buf+rc, PAGE_SIZE,  "Excursion={ %d, %d, %d, %d, %d, %d, %d, %d, %d, %d,\n",  
						exCurLogArray[0], exCurLogArray[1], exCurLogArray[2], exCurLogArray[3], exCurLogArray[4],
						exCurLogArray[5], exCurLogArray[6], exCurLogArray[7], exCurLogArray[8], exCurLogArray[9]);
		rc += snprintf(buf+rc, PAGE_SIZE,  "            %d, %d, %d, %d, %d, %d, %d, %d, %d, %d }\n",  
						AfterexCurLogArray[0], AfterexCurLogArray[1], AfterexCurLogArray[2], AfterexCurLogArray[3], AfterexCurLogArray[4],
						AfterexCurLogArray[5], AfterexCurLogArray[6], AfterexCurLogArray[7], AfterexCurLogArray[8], AfterexCurLogArray[9]);
		rc += snprintf(buf+rc, PAGE_SIZE,  "Rdc={ %d, %d, %d, %d, %d, %d, %d, %d, %d, %d,\n",  
						rdcLogArray[0], rdcLogArray[1], rdcLogArray[2], rdcLogArray[3], rdcLogArray[4],
						rdcLogArray[5], rdcLogArray[6], rdcLogArray[7], rdcLogArray[8], rdcLogArray[9]);
		rc += snprintf(buf+rc, PAGE_SIZE,  "      %d, %d, %d, %d, %d, %d, %d, %d, %d, %d }\n",  
						AfterrdcLogArray[0], AfterrdcLogArray[1], AfterrdcLogArray[2], AfterrdcLogArray[3], AfterrdcLogArray[4],
						AfterrdcLogArray[5], AfterrdcLogArray[6], AfterrdcLogArray[7], AfterrdcLogArray[8], AfterrdcLogArray[9]);
		rc += snprintf(buf+rc, PAGE_SIZE,  "Frequency={ %d, %d, %d, %d, %d, %d, %d, %d, %d, %d,\n",  
						freqLogArray[0], freqLogArray[1], freqLogArray[2], freqLogArray[3], freqLogArray[4],
						freqLogArray[5], freqLogArray[6], freqLogArray[7], freqLogArray[8], freqLogArray[9]);
		rc += snprintf(buf+rc, PAGE_SIZE,  "            %d, %d, %d, %d, %d, %d, %d, %d, %d, %d }\n",  
						AfterfreqLogArray[0], AfterfreqLogArray[1], AfterfreqLogArray[2], AfterfreqLogArray[3], AfterfreqLogArray[4],
						AfterfreqLogArray[5], AfterfreqLogArray[6], AfterfreqLogArray[7], AfterfreqLogArray[8], AfterfreqLogArray[9]);
	}

#ifdef USE_DSM_MISC_DEV	
	rc += snprintf(buf+rc, PAGE_SIZE,  "[Parameter Set] excursionlimit:0x%x, rdcroomtemp:0x%x, coilthermallimit:0x%x, releasetime:0x%x\n",
					param_dsm[param_excur_limit],
					param_dsm[param_voice_coil],
					param_dsm[param_thermal_limit],
					param_dsm[param_release_time]);
	rc += snprintf(buf+rc, PAGE_SIZE,  "[Parameter Set] staticgain:0x%x, lfxgain:0x%x, pilotgain:0x%dx\n",
					param_dsm[param_static_gain],
					param_dsm[param_lfx_gain],
					param_dsm[param_pilot_gain]);
#endif /* USE_DSM_MISC_DEV */

out:
	max98504_dsm_log_free((void**)&byteLogArray, (void**)&intLogArray, (void**)&afterbyteLogArray, (void**)&afterintLogArray);

	return (ssize_t)rc;
}

static DEVICE_ATTR(dsm_log, S_IRUGO, max98504_dsm_log_show, NULL);

static struct attribute *max98504_attributes[] = {
	&dev_attr_dsm_log.attr,
	NULL
};

static struct attribute_group max98504_attribute_group = {
	.attrs = max98504_attributes
};
#endif /* USE_DSM_LOG */

static int max98504_probe(struct snd_soc_codec *codec)
{
	struct max98504_priv *max98504 = snd_soc_codec_get_drvdata(codec);
	struct max98504_cdata *cdata;
	int ret = 0;

	msg_maxim("\n");

	max98504->codec = codec;

	codec->cache_sync = 1;

	ret = snd_soc_codec_set_cache_io(codec, 16, 8, SND_SOC_I2C);
	if (ret != 0) {
		dev_err(codec->dev, "Failed to set cache I/O: %d\n", ret);
		return ret;
	}

	/* reset the codec, the DSP core, and disable all interrupts */
	ret = max98504_reset(codec);
	if (ret < 0) {
		goto err_access;
	}

	/* initialize private data */

	max98504->sysclk = (unsigned)-1;

	cdata = &max98504->dai[0];
	cdata->rate = (unsigned)-1;
	cdata->fmt  = (unsigned)-1;

	ret = snd_soc_read(codec, MAX98504_REG_7FFF_REV_ID);
	if (ret < 0) {
		dev_err(codec->dev, "Failed to read device revision: %d\n",
			ret);
		goto err_access;
	}
	msg_maxim("REV ID=0x%d\n", ret);

	// Do this command for SSM, DEM enable.
	snd_soc_write(codec, MAX98504_REG_7FFF_REV_ID, 0x54);
	snd_soc_write(codec, MAX98504_REG_7FFF_REV_ID, 0x4d);

#ifdef MAX98504_WATCHDOG_ENABLE
	snd_soc_write(codec, MAX98504_REG_03_INTERRUPT_ENABLES, M98504_INT_WATCHFAIL_EN_MASK);
	snd_soc_write(codec, MAX98504_REG_10_GPIO_ENABLE, M98504_GPIO_ENABLE_MASK);
	snd_soc_write(codec, MAX98504_REG_04_INTERRUPT_FLAG_CLEARS, 0xFF);

	if ( (request_threaded_irq(pdata->irq, NULL,
		max98504_interrupt, IRQF_TRIGGER_FALLING,
		"max98504_interrupt", codec)) < 0) {
		msg_maxim("request_irq failed\n");
	}
#endif

#if 1
	snd_soc_write(codec, MAX98504_REG_16_PVDD_BROWNOUT_ENABLE, 0x1);
	snd_soc_write(codec, MAX98504_REG_17_PVDD_BROWNOUT_CONFIG_1, 0x3);
	snd_soc_write(codec, MAX98504_REG_18_PVDD_BROWNOUT_CONFIG_2, 0x64);
	snd_soc_write(codec, MAX98504_REG_19_PVDD_BROWNOUT_CONFIG_3, 0xff);
	snd_soc_write(codec, MAX98504_REG_1A_PVDD_BROWNOUT_CONFIG_4, 0xff);
#endif

	max98504_handle_pdata(codec);
	max98504_add_widgets(codec);

#ifdef MAX98504_WATCHDOG_ENABLE
	INIT_DELAYED_WORK_DEFERRABLE(&max98504->work, max98504_work);
#endif

#ifdef USE_DSM_LOG
	ret = sysfs_create_group(&codec->dev->kobj, &max98504_attribute_group);
	if(ret)	{
		msg_maxim("failed to create sysfs group [%d]", ret);
	}
#endif
	msg_maxim("done.");

err_access:
	return ret;
}

static int max98504_remove(struct snd_soc_codec *codec)
{
	msg_maxim("\n");

	return 0;
}

static struct snd_soc_codec_driver soc_codec_dev_max98504 = {
	.probe   = max98504_probe,
	.remove  = max98504_remove,
	.suspend = max98504_suspend,
	.resume  = max98504_resume,
	.set_bias_level = max98504_set_bias_level,
	.reg_cache_size = ARRAY_SIZE(max98504_reg_def),
	.reg_word_size = sizeof(u8),
	.reg_cache_default = max98504_reg_def,
	.readable_register = max98504_readable,
	.volatile_register = max98504_volatile_register,
	.dapm_widgets	  = max98504_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(max98504_dapm_widgets),
	.dapm_routes     = max98504_audio_map,
	.num_dapm_routes = ARRAY_SIZE(max98504_audio_map),
};

#ifdef SUPPORT_DEVICE_TREE
static int reg_set_optimum_mode_check(struct regulator *reg, int load_uA)
{
	return (regulator_count_voltages(reg) > 0) ?
			regulator_set_optimum_mode(reg, load_uA) : 0;
}

static int max98504_regulator_config(struct i2c_client *i2c, bool pullup, bool on)
{
	struct regulator *max98504_vcc_i2c;
	int rc;
    #define VCC_I2C_MIN_UV	1800000
    #define VCC_I2C_MAX_UV	1800000
	#define I2C_LOAD_UA		300000

	if (pullup) {
		max98504_vcc_i2c = regulator_get(&i2c->dev, "vcc_i2c");

		if (IS_ERR(max98504_vcc_i2c)) {
			rc = PTR_ERR(max98504_vcc_i2c);
			pr_info("Regulator get failed rc=%d\n",	rc);
			goto error_get_vtg_i2c;
		}

		if (regulator_count_voltages(max98504_vcc_i2c) > 0) {
			rc = regulator_set_voltage(max98504_vcc_i2c, VCC_I2C_MIN_UV, VCC_I2C_MAX_UV);
			if (rc) {
				pr_info("regulator set_vtg failed rc=%d\n", rc);
				goto error_set_vtg_i2c;
			}
		}

		rc = reg_set_optimum_mode_check(max98504_vcc_i2c, I2C_LOAD_UA);
		if (rc < 0) {
			pr_info("Regulator vcc_i2c set_opt failed rc=%d\n", rc);
			goto error_reg_opt_i2c;
		}
		
		rc = regulator_enable(max98504_vcc_i2c);
		if (rc) {
			pr_info("Regulator vcc_i2c enable failed rc=%d\n", rc);
			goto error_reg_en_vcc_i2c;
		}
	}

	return 0;

	error_set_vtg_i2c:
		regulator_put(max98504_vcc_i2c);
	error_get_vtg_i2c:
		if (regulator_count_voltages(max98504_vcc_i2c) > 0)
			regulator_set_voltage(max98504_vcc_i2c, 0, VCC_I2C_MAX_UV);
	error_reg_en_vcc_i2c:
		if(pullup) 	reg_set_optimum_mode_check(max98504_vcc_i2c, 0);
	error_reg_opt_i2c:
		regulator_disable(max98504_vcc_i2c);

	return rc;
}
#endif

static int max98504_i2c_probe(struct i2c_client *i2c,
			     const struct i2c_device_id *id)
{
	struct max98504_priv *max98504;
	int ret;

	msg_maxim("\n");

#ifdef SUPPORT_DEVICE_TREE
	max98504_regulator_config(i2c, of_property_read_bool(i2c->dev.of_node, "max98504,i2c-pull-up"), 1);
#endif

#if 0
	max98504_config.irq = of_get_named_gpio_flags(i2c->dev.of_node, "max98504,irq-gpio",
		0, &pdata->irq_gpio_flags);
#endif

	max98504 = kzalloc(sizeof(struct max98504_priv), GFP_KERNEL);
	if (max98504 == NULL)
		return -ENOMEM;

	max98504->devtype = id->driver_data;
	i2c_set_clientdata(i2c, max98504);
	max98504->control_data = i2c;
	max98504->pdata = i2c->dev.platform_data;

	ret = snd_soc_register_codec(&i2c->dev, &soc_codec_dev_max98504, max98504_dai, ARRAY_SIZE(max98504_dai));

	msg_maxim("ret=%d\n", ret);

	if (ret < 0)
		kfree(max98504);

	return ret;
}

static int __devexit max98504_i2c_remove(struct i2c_client *client)
{
	snd_soc_unregister_codec(&client->dev);
	kfree(i2c_get_clientdata(client));

	msg_maxim("\n");

	return 0;
}

static const struct i2c_device_id max98504_i2c_id[] = {
	{ "max98504", MAX98504 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, max98504_i2c_id);

static struct i2c_driver max98504_i2c_driver = {
	.driver = {
		.name = "max98504",
		.owner = THIS_MODULE,
	},
	.probe  = max98504_i2c_probe,
	.remove = __devexit_p(max98504_i2c_remove),
	.id_table = max98504_i2c_id,
};

#ifdef USE_DSM_MISC_DEV
int get_dsm_onoff_status(void)
{
#ifdef DSM_ALWAYS_ON
	return 1;
#else
	return param_dsm[param_onoff];
#endif
}

static void set_dsm_onoff_status(int onoff)
{
#ifdef DSM_ALWAYS_ON
	param_dsm[param_onoff] = 1;
#else
	param_dsm[param_onoff] = onoff;
#endif
}

static void write_param(int *param)
{
	uint32_t filter_set;
    int32_t port_id =0x4000; //hardcoded to slimbus
	int x;
#ifdef DSM_ALWAYS_ON
	param[param_onoff] = 1;
#endif
	if(param[param_wirte_flag] == 0)	{
		// validation check
		param[param_wirte_flag] = 0;
		for(x=0;x<param_max;x+=2)	{
			if(x!= param_onoff && param_dsm[x]!=0) {
				param[param_wirte_flag] = 0xabefcdab;
				break;
			}
		}		
	}

	if(param[param_wirte_flag]==0xabefcdab || param[param_wirte_flag] == 0xcdababef) {
		memcpy(param_dsm, param, sizeof(param_dsm));

	/* set params from the algorithm to application */
		filter_set = 3;	// SET PARAM
		dsm_open(port_id, &filter_set, (u8*)param);
	}
}

static void read_param(int *param)
{
	uint32_t filter_set;
	int32_t port_id =0x4000; // Port ID for SLIMBUS RX0
	
	filter_set = 2;	// GET PARAM
	dsm_open(port_id, &filter_set, (u8*)param);
	memcpy(param_dsm, param, sizeof(param_dsm));
	if(param_dsm[param_excur_limit]!=0 && param_dsm[param_thermal_limit]!=0)	{
		newLogAvail |= 0x1;
	}
}

#ifdef USE_DSM_LOG
static void dsm_dump_func(int onoff)
{
	static int param[param_max];

	msg_maxim("%s\n", __func__);

	mutex_lock(&dsm_lock);
	read_param((int*)param);
	#if 0
	param[param_wirte_flag] = 0xaabbccdd;
	write_param(param);
	#endif
	mutex_unlock(&dsm_lock);
}
#endif

static int __devexit dsm_ctrl_remove(struct i2c_client *client)
{
	return 0;
}

static int dsm_ctrl_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int dsm_ctrl_release(struct inode *inode, struct file *file)
{
	return 0;	
}

static ssize_t dsm_ctrl_read(struct file *fp, char __user *buf,
			 size_t count, loff_t *pos)
{
	int rc;

	static int param[param_max];
	mutex_lock(&dsm_lock);

	read_param((int*)param);

	rc = copy_to_user(buf, param, count);
	if (rc != 0) {
		pr_err("copy_to_user failed. (rc=%d)\n", rc);
		mutex_unlock(&dsm_lock);
		return 0;
	}

	mutex_unlock(&dsm_lock);

	return rc;
}

static ssize_t dsm_ctrl_write(struct file *file,
				const char __user *buf,
				size_t count,
				loff_t *ppos)
{
	int rc=0;
	static int param[param_max];

	mutex_lock(&dsm_lock);

	rc = copy_from_user(param, buf, count);
	if (rc != 0) {
		pr_err("copy_from_user failed. (rc=%d)", rc);
		mutex_unlock(&dsm_lock);
		return rc;
	}

	write_param((int*)param);
	mutex_unlock(&dsm_lock);

	return rc;
}

static struct file_operations dsm_ctrl_fops = {
	.owner		= THIS_MODULE,
	.open		= dsm_ctrl_open,
	.release	= dsm_ctrl_release,
	.read = dsm_ctrl_read,
	.write = dsm_ctrl_write,
};
static struct miscdevice dsm_ctrl_miscdev = {
	.minor =    MISC_DYNAMIC_MINOR,
	.name =     "dsm_ctrl_dev0",
	.fops =     &dsm_ctrl_fops
};

static int dsm_misc_device_init(void)
{
    int result=0;

    result = misc_register(&dsm_ctrl_miscdev);

    return result;
}

static int dsm_misc_device_deinit(void)
{
    int result=0;

    result = misc_deregister(&dsm_ctrl_miscdev);

    return result;
}
#endif

static int __init max98504_init(void)
{
	int ret;

	msg_maxim("%s\n", __func__);

#ifdef USE_DSM_MISC_DEV
	memset(param_dsm, 0, sizeof(param_dsm));
#endif

	ret = i2c_add_driver(&max98504_i2c_driver);

	if (ret)
		pr_err("Failed to register MAX98504 I2C driver: %d\n", ret);
	else
		pr_info("MAX98504 driver built on %s at %s\n", __DATE__, __TIME__);

#ifdef USE_DSM_MISC_DEV
	dsm_misc_device_init();
#endif

	return ret;
}
module_init(max98504_init);

static void __exit max98504_exit(void)
{
	i2c_del_driver(&max98504_i2c_driver);
#ifdef USE_DSM_MISC_DEV
	dsm_misc_device_deinit();
#endif
}
module_exit(max98504_exit);

MODULE_DESCRIPTION("ALSA SoC MAX98504 driver");
MODULE_AUTHOR("Ryan Lee");
MODULE_LICENSE("GPL");
