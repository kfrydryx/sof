# SPDX-License-Identifier: BSD-3-Clause

if(BUILD_LIBRARY)
	return()
endif()

add_local_sources(sof numbers.c)

if(CONFIG_CORDIC_FIXED)
        add_local_sources(sof trig.c)
endif()

if(CONFIG_SQRT_FIXED)
        add_local_sources(sof sqrt_int16.c)
endif()

if(CONFIG_MATH_DECIBELS)
        add_local_sources(sof decibels.c)
endif()

if(CONFIG_POWER_FIXED)
	 add_local_sources(sof power.c)
endif()

if(CONFIG_BINARY_LOGARITHM_FIXED)
	 add_local_sources(sof base2log.c)
endif()

if(CONFIG_MATH_FIR)
        add_local_sources(sof fir_generic.c fir_hifi2ep.c fir_hifi3.c)
endif()

if(CONFIG_MATH_FFT)
	add_subdirectory(fft)
endif()

if(CONFIG_MATH_IIR_DF2T)
        add_local_sources(sof iir_df2t_generic.c iir_df2t_hifi3.c)
endif()
