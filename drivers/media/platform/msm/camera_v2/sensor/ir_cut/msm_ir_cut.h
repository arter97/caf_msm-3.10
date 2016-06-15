/* Copyright (c) 2016, The Linux Foundation. All rights reserved.
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

#ifndef MSM_IR_CUT_H
#define MSM_IR_CUT_H

#include <linux/platform_device.h>
#include <media/v4l2-subdev.h>
#include <media/v4l2-ioctl.h>
#include <media/msm_cam_sensor.h>
#include <soc/qcom/camera2.h>
#include "msm_sd.h"

#define DEFINE_MSM_MUTEX(mutexname) \
	static struct mutex mutexname = __MUTEX_INITIALIZER(mutexname)

enum msm_camera_ir_cut_state_t {
	MSM_CAMERA_IR_CUT_INIT,
	MSM_CAMERA_IR_CUT_RELEASE,
};

struct msm_ir_cut_ctrl_t;

struct msm_ir_cut_func_t {
	int32_t (*camera_ir_cut_init)(struct msm_ir_cut_ctrl_t *,
		struct msm_ir_cut_cfg_data_t *);
	int32_t (*camera_ir_cut_release)(struct msm_ir_cut_ctrl_t *);
	int32_t (*camera_ir_cut_off)(struct msm_ir_cut_ctrl_t *,
		struct msm_ir_cut_cfg_data_t *);
	int32_t (*camera_ir_cut_on)(struct msm_ir_cut_ctrl_t *,
		struct msm_ir_cut_cfg_data_t *);
};

struct msm_ir_cut_table {
	enum msm_ir_cut_driver_type ir_cut_driver_type;
	struct msm_ir_cut_func_t func_tbl;
};

struct msm_ir_cut_ctrl_t {
	struct msm_sd_subdev msm_sd;
	struct platform_device *pdev;
	struct msm_ir_cut_func_t *func_tbl;
	struct msm_camera_power_ctrl_t power_info;

	enum msm_camera_device_type_t ir_cut_device_type;
	struct mutex *ir_cut_mutex;

	/* ir_cut driver type */
	enum msm_ir_cut_driver_type ir_cut_driver_type;

	/* ir_cut state */
	enum msm_camera_ir_cut_state_t ir_cut_state;
};

#endif
