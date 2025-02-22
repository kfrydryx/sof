`# Topology for generic' PLATFORM `board with' CODEC `on SSP' SSP_NUM

# Include topology builder
include(`utils.m4')
include(`dai.m4')
include(`pipeline.m4')
include(`ssp.m4')

# Include TLV library
include(`common/tlv.m4')

# Include Token library
include(`sof/tokens.m4')

# Include DSP configuration
include(`platform/intel/'PLATFORM`.m4')

#
# Define the pipelines
#
# PCM0 -----> volume -------v
#                            low latency mixer ----> volume ---->  SSP2
# PCM1 -----> volume -------^
# PCM0 <---- Volume <---- SSP2
#

# Low Latency capture pipeline 2 on PCM 0 using max 2 channels of s16le.
# 1000us deadline with priority 0 on core 0
PIPELINE_PCM_ADD(sof/pipe-low-latency-capture.m4,
	2, 0, 2, s16le,
	1000, 0, 0,
	48000, 48000, 48000)

#
# DAI configuration
#
# SSP port 2 is our only pipeline DAI
#

# playback DAI is SSP2 using 2 periods
# Buffers use s16le format, 1000us deadline on core 0 with priority 1
# this defines pipeline 1. The 'NOT_USED_IGNORED' is due to dependencies
# and is adjusted later with an explicit dapm line.
DAI_ADD(sof/pipe-mixer-volume-dai-playback.m4,
	1, SSP, SSP_NUM, SSP2-Codec,
	NOT_USED_IGNORED, 2, s16le,
	1000, 1, 0, SCHEDULE_TIME_DOMAIN_DMA,
	2, 48000)

# PCM Playback pipeline 3 on PCM 0 using max 2 channels of s16le.
# 1000us deadline with priority 0 on core 0
# this is connected to pipeline DAI 1
PIPELINE_PCM_ADD(sof/pipe-host-volume-playback.m4,
	3, 0, 2, s16le,
	1000, 0, 0,
	48000, 48000, 48000,
	SCHEDULE_TIME_DOMAIN_DMA,
	PIPELINE_PLAYBACK_SCHED_COMP_1)

# PCM Playback pipeline 4 on PCM 1 using max 2 channels of s16le.
# 10ms deadline with priority 0 on core 0
# this is connected to pipeline DAI 1
PIPELINE_PCM_ADD(sof/pipe-host-volume-playback.m4,
	4, 1, 2, s16le,
	10000, 0, 0,
	48000, 48000, 48000,
	SCHEDULE_TIME_DOMAIN_DMA,
	PIPELINE_PLAYBACK_SCHED_COMP_1)

# Connect pipelines together
SectionGraph."PIPE_NAME" {
	index "0"

	lines [
		# PCM pipeline 3 to DAI pipeline 1
		dapm(PIPELINE_MIXER_1, PIPELINE_SOURCE_3)
		# PCM pipeline 4 to DAI pipeline 1
		dapm(PIPELINE_MIXER_1, PIPELINE_SOURCE_4)

	]
}

# capture DAI is SSP2 using 2 periods
# Buffers use s16le format, 1000us deadline with priority 0 on core 0
# this is part of pipeline 2
DAI_ADD(sof/pipe-dai-capture.m4,
	2, SSP, SSP_NUM, SSP2-Codec,
	PIPELINE_SINK_2, 2, s16le,
	1000, 0, 0, SCHEDULE_TIME_DOMAIN_DMA)


# PCM definitions
PCM_DUPLEX_ADD(PCM, 0, PIPELINE_PCM_3, PIPELINE_PCM_2)
PCM_PLAYBACK_ADD(PCM Deep Buffer, 1, PIPELINE_PCM_4)

#
# BE configurations - overrides config in ACPI if present
#
DAI_CONFIG(SSP, SSP_NUM, 0, SSP2-Codec,
	   SSP_CONFIG(I2S, SSP_CLOCK(mclk, 19200000, codec_mclk_in),
		      SSP_CLOCK(bclk, 1920000, codec_consumer),
		      SSP_CLOCK(fsync, 48000, codec_consumer),
		      SSP_TDM(2, 20, 3, 3),
		      SSP_CONFIG_DATA(SSP, 2, 16)))

VIRTUAL_WIDGET(ssp2 Rx, out_drv, 1)
VIRTUAL_WIDGET(ssp2 Tx, out_drv, 2)
