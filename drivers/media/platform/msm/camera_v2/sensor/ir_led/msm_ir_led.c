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

#define pr_fmt(fmt) "%s:%d " fmt, __func__, __LINE__

#include <linux/module.h>
#include <linux/of_gpio.h>
#include "msm_ir_led.h"
#include "msm_camera_dt_util.h"

#undef CDBG
#define CDBG(fmt, args...) pr_debug(fmt, ##args)

DEFINE_MSM_MUTEX(msm_ir_led_mutex);

static struct v4l2_file_operations msm_ir_led_v4l2_subdev_fops;

static const struct of_device_id msm_ir_led_dt_match[] = {
	{.compatible = "qcom,ir-led", .data = NULL},
	{}
};

static struct msm_ir_led_table msm_gpio_ir_led_table;

static struct msm_ir_led_table *ir_led_table[] = {
	&msm_gpio_ir_led_table,
};

static int32_t msm_ir_led_get_subdev_id(
	struct msm_ir_led_ctrl_t *ir_led_ctrl, void *arg)
{
	uint32_t *subdev_id = (uint32_t *)arg;
	CDBG("Enter\n");
	if (!subdev_id) {
		pr_err("failed\n");
		return -EINVAL;
	}
	if (MSM_CAMERA_PLATFORM_DEVICE != ir_led_ctrl->ir_led_device_type) {
		pr_err("failed\n");
		return -EINVAL;
	}

	*subdev_id = ir_led_ctrl->pdev->id;

	CDBG("subdev_id %d\n", *subdev_id);
	CDBG("Exit\n");
	return 0;
}

static int32_t msm_ir_led_init(
	struct msm_ir_led_ctrl_t *ir_led_ctrl,
	struct msm_ir_led_cfg_data_t *ir_led_data)
{
	int32_t rc = 0;

	CDBG("Enter");

	rc = ir_led_ctrl->func_tbl->camera_ir_led_off(ir_led_ctrl, ir_led_data);

	CDBG("Exit");
	return rc;
}

static int32_t msm_ir_led_release(
	struct msm_ir_led_ctrl_t *ir_led_ctrl)
{
	int32_t rc = 0;
	if (ir_led_ctrl->ir_led_state == MSM_CAMERA_IR_LED_RELEASE) {
		pr_err("%s:%d Invalid ir_led state = %d",
			__func__, __LINE__, ir_led_ctrl->ir_led_state);
		return 0;
	}

	rc = ir_led_ctrl->func_tbl->camera_ir_led_off(ir_led_ctrl, NULL);
	if (rc < 0) {
		pr_err("%s:%d camera_ir_led_off failed rc = %d",
			__func__, __LINE__, rc);
		return rc;
	}
	ir_led_ctrl->ir_led_state = MSM_CAMERA_IR_LED_RELEASE;
	return 0;
}

static int32_t msm_ir_led_off(struct msm_ir_led_ctrl_t *ir_led_ctrl,
	struct msm_ir_led_cfg_data_t *ir_led_data)
{
	CDBG("Enter\n");

	CDBG("Exit\n");
	return 0;
}

static int32_t msm_ir_led_on(
	struct msm_ir_led_ctrl_t *ir_led_ctrl,
	struct msm_ir_led_cfg_data_t *ir_led_data)
{
	CDBG("Enter\n");

	CDBG("intensity %d\n", ir_led_data->intensity);

	CDBG("Exit\n");
	return 0;
}

static int32_t msm_ir_led_handle_init(
	struct msm_ir_led_ctrl_t *ir_led_ctrl,
	struct msm_ir_led_cfg_data_t *ir_led_data)
{
	uint32_t i = 0;
	int32_t rc = -EFAULT;
	enum msm_ir_led_driver_type ir_led_driver_type =
		ir_led_ctrl->ir_led_driver_type;

	CDBG("Enter");

	if (ir_led_ctrl->ir_led_state == MSM_CAMERA_IR_LED_INIT) {
		pr_err("%s:%d Invalid ir_led state = %d",
			__func__, __LINE__, ir_led_ctrl->ir_led_state);
		return 0;
	}

	for (i = 0; i < ARRAY_SIZE(ir_led_table); i++) {
		if (ir_led_driver_type == ir_led_table[i]->ir_led_driver_type) {
			ir_led_ctrl->func_tbl = &ir_led_table[i]->func_tbl;
			rc = 0;
			break;
		}
	}

	if (rc < 0) {
		pr_err("%s:%d failed invalid ir_led_driver_type %d\n",
			__func__, __LINE__, ir_led_driver_type);
		return -EINVAL;
	}

	rc = ir_led_ctrl->func_tbl->camera_ir_led_init(
		ir_led_ctrl, ir_led_data);
	if (rc < 0) {
		pr_err("%s:%d camera_ir_led_init failed rc = %d",
			__func__, __LINE__, rc);
		return rc;
	}

	ir_led_ctrl->ir_led_state = MSM_CAMERA_IR_LED_INIT;

	CDBG("Exit");
	return 0;
}

static int32_t msm_ir_led_config(struct msm_ir_led_ctrl_t *ir_led_ctrl,
	void __user *argp)
{
	int32_t rc = -EINVAL;
	struct msm_ir_led_cfg_data_t *ir_led_data =
		(struct msm_ir_led_cfg_data_t *) argp;

	mutex_lock(ir_led_ctrl->ir_led_mutex);

	CDBG("Enter %s type %d\n", __func__, ir_led_data->cfg_type);

	switch (ir_led_data->cfg_type) {
	case CFG_IR_LED_INIT:
		rc = msm_ir_led_handle_init(ir_led_ctrl, ir_led_data);
		break;
	case CFG_IR_LED_RELEASE:
		if (ir_led_ctrl->ir_led_state == MSM_CAMERA_IR_LED_INIT)
			rc = ir_led_ctrl->func_tbl->camera_ir_led_release(
				ir_led_ctrl);
		break;
	case CFG_IR_LED_OFF:
		if (ir_led_ctrl->ir_led_state == MSM_CAMERA_IR_LED_INIT)
			rc = ir_led_ctrl->func_tbl->camera_ir_led_off(
				ir_led_ctrl, ir_led_data);
		break;
	case CFG_IR_LED_ON:
		if (ir_led_ctrl->ir_led_state == MSM_CAMERA_IR_LED_INIT)
			rc = ir_led_ctrl->func_tbl->camera_ir_led_on(
				ir_led_ctrl, ir_led_data);
		break;
	default:
		rc = -EFAULT;
		break;
	}

	mutex_unlock(ir_led_ctrl->ir_led_mutex);

	CDBG("Exit %s type %d\n", __func__, ir_led_data->cfg_type);

	return rc;
}

static long msm_ir_led_subdev_ioctl(struct v4l2_subdev *sd,
	unsigned int cmd, void *arg)
{
	struct msm_ir_led_ctrl_t *fctrl = NULL;
	void __user *argp = (void __user *)arg;

	CDBG("Enter\n");

	if (!sd) {
		pr_err("sd NULL\n");
		return -EINVAL;
	}
	fctrl = v4l2_get_subdevdata(sd);
	if (!fctrl) {
		pr_err("fctrl NULL\n");
		return -EINVAL;
	}
	switch (cmd) {
	case VIDIOC_MSM_SENSOR_GET_SUBDEV_ID:
		return msm_ir_led_get_subdev_id(fctrl, argp);
	case VIDIOC_MSM_IR_LED_CFG:
		return msm_ir_led_config(fctrl, argp);
	case MSM_SD_NOTIFY_FREEZE:
		return 0;
	case MSM_SD_SHUTDOWN:
		if (!fctrl->func_tbl) {
			pr_err("fctrl->func_tbl NULL\n");
			return -EINVAL;
		} else {
			return fctrl->func_tbl->camera_ir_led_release(fctrl);
		}
	default:
		pr_err_ratelimited("invalid cmd %d\n", cmd);
		return -ENOIOCTLCMD;
	}
	CDBG("Exit\n");
}

static struct v4l2_subdev_core_ops msm_ir_led_subdev_core_ops = {
	.ioctl = msm_ir_led_subdev_ioctl,
};

static struct v4l2_subdev_ops msm_ir_led_subdev_ops = {
	.core = &msm_ir_led_subdev_core_ops,
};

static const struct v4l2_subdev_internal_ops msm_ir_led_internal_ops;

static int32_t msm_ir_led_get_gpio_dt_data(struct device_node *of_node,
	struct msm_ir_led_ctrl_t *fctrl)
{
	int32_t rc = 0, i = 0;
	uint16_t *gpio_array = NULL;
	int16_t gpio_array_size = 0;
	struct msm_camera_gpio_conf *gconf = NULL;

	gpio_array_size = of_gpio_count(of_node);
	CDBG("%s gpio count %d\n", __func__, gpio_array_size);

	if (gpio_array_size > 0) {
		fctrl->power_info.gpio_conf =
			 kzalloc(sizeof(struct msm_camera_gpio_conf),
				 GFP_KERNEL);
		if (!fctrl->power_info.gpio_conf) {
			pr_err("%s failed %d\n", __func__, __LINE__);
			rc = -ENOMEM;
			return rc;
		}
		gconf = fctrl->power_info.gpio_conf;

		gpio_array = kzalloc(sizeof(uint16_t) * gpio_array_size,
			GFP_KERNEL);
		if (!gpio_array) {
			pr_err("%s failed %d\n", __func__, __LINE__);
			rc = -ENOMEM;
			goto free_gpio_conf;
		}
		for (i = 0; i < gpio_array_size; i++) {
			gpio_array[i] = of_get_gpio(of_node, i);
			if (((int16_t)gpio_array[i]) < 0) {
				pr_err("%s failed %d\n", __func__, __LINE__);
				rc = -EINVAL;
				goto free_gpio_array;
			}
			CDBG("%s gpio_array[%d] = %d\n", __func__, i,
				gpio_array[i]);
		}

		rc = msm_camera_get_dt_gpio_req_tbl(of_node, gconf,
			gpio_array, gpio_array_size);
		if (rc < 0) {
			pr_err("%s failed %d\n", __func__, __LINE__);
			goto free_gpio_array;
		}
		kfree(gpio_array);

		if (fctrl->ir_led_driver_type == IR_LED_DRIVER_DEFAULT)
			fctrl->ir_led_driver_type = IR_LED_DRIVER_GPIO;
		CDBG("%s:%d fctrl->ir_led_driver_type = %d", __func__, __LINE__,
			fctrl->ir_led_driver_type);
	}

	return rc;

free_gpio_array:
	kfree(gpio_array);
free_gpio_conf:
	kfree(fctrl->power_info.gpio_conf);
	return rc;
}

static int32_t msm_ir_led_get_dt_data(struct device_node *of_node,
	struct msm_ir_led_ctrl_t *fctrl)
{
	int32_t rc = 0;

	CDBG("called\n");

	if (!of_node) {
		pr_err("of_node NULL\n");
		return -EINVAL;
	}

	/* Read the sub device */
	rc = of_property_read_u32(of_node, "cell-index", &fctrl->pdev->id);
	if (rc < 0) {
		pr_err("failed rc %d\n", rc);
		return rc;
	}

	fctrl->ir_led_driver_type = IR_LED_DRIVER_DEFAULT;

	/* Read the gpio information from device tree */
	rc = msm_ir_led_get_gpio_dt_data(of_node, fctrl);
	if (rc < 0) {
		pr_err("%s:%d msm_ir_led_get_gpio_dt_data failed rc %d\n",
			__func__, __LINE__, rc);
		return rc;
	}

	return rc;
}

#ifdef CONFIG_COMPAT
static long msm_ir_led_subdev_do_ioctl(
	struct file *file, unsigned int cmd, void *arg)
{
	int32_t rc = 0;
	struct video_device *vdev = video_devdata(file);
	struct v4l2_subdev *sd = vdev_to_v4l2_subdev(vdev);
	struct msm_ir_led_cfg_data_t32 *u32 =
		(struct msm_ir_led_cfg_data_t32 *)arg;
	struct msm_ir_led_cfg_data_t ir_led_data;

	CDBG("Enter");
	ir_led_data.cfg_type = u32->cfg_type;
	ir_led_data.intensity = u32->intensity;

	switch (cmd) {
	case VIDIOC_MSM_IR_LED_CFG32:
		cmd = VIDIOC_MSM_IR_LED_CFG;
		break;
	default:
		return msm_ir_led_subdev_ioctl(sd, cmd, arg);
	}

	rc = msm_ir_led_subdev_ioctl(sd, cmd, &ir_led_data);

	CDBG("Exit");
	return rc;
}

static long msm_ir_led_subdev_fops_ioctl(struct file *file,
	unsigned int cmd, unsigned long arg)
{
	return video_usercopy(file, cmd, arg, msm_ir_led_subdev_do_ioctl);
}
#endif

static int32_t msm_ir_led_platform_probe(struct platform_device *pdev)
{
	int32_t rc = 0;
	struct msm_ir_led_ctrl_t *ir_led_ctrl = NULL;

	CDBG("Enter");
	if (!pdev->dev.of_node) {
		pr_err("of_node NULL\n");
		return -EINVAL;
	}

	ir_led_ctrl = kzalloc(sizeof(struct msm_ir_led_ctrl_t), GFP_KERNEL);
	if (!ir_led_ctrl) {
		pr_err("%s:%d failed no memory\n", __func__, __LINE__);
		return -ENOMEM;
	}

	memset(ir_led_ctrl, 0, sizeof(struct msm_ir_led_ctrl_t));

	ir_led_ctrl->pdev = pdev;

	rc = msm_ir_led_get_dt_data(pdev->dev.of_node, ir_led_ctrl);
	if (rc < 0) {
		pr_err("%s:%d msm_ir_led_get_dt_data failed\n",
			__func__, __LINE__);
		kfree(ir_led_ctrl);
		return -EINVAL;
	}

	ir_led_ctrl->ir_led_state = MSM_CAMERA_IR_LED_RELEASE;
	ir_led_ctrl->power_info.dev = &ir_led_ctrl->pdev->dev;
	ir_led_ctrl->ir_led_device_type = MSM_CAMERA_PLATFORM_DEVICE;
	ir_led_ctrl->ir_led_mutex = &msm_ir_led_mutex;

	/* Initialize sub device */
	v4l2_subdev_init(&ir_led_ctrl->msm_sd.sd, &msm_ir_led_subdev_ops);
	v4l2_set_subdevdata(&ir_led_ctrl->msm_sd.sd, ir_led_ctrl);

	ir_led_ctrl->msm_sd.sd.internal_ops = &msm_ir_led_internal_ops;
	ir_led_ctrl->msm_sd.sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
	snprintf(ir_led_ctrl->msm_sd.sd.name,
		ARRAY_SIZE(ir_led_ctrl->msm_sd.sd.name),
		"msm_camera_ir_led");
	media_entity_init(&ir_led_ctrl->msm_sd.sd.entity, 0, NULL, 0);
	ir_led_ctrl->msm_sd.sd.entity.type = MEDIA_ENT_T_V4L2_SUBDEV;
	ir_led_ctrl->msm_sd.sd.entity.group_id = MSM_CAMERA_SUBDEV_IR_LED;
	ir_led_ctrl->msm_sd.close_seq = MSM_SD_CLOSE_2ND_CATEGORY | 0x1;
	msm_sd_register(&ir_led_ctrl->msm_sd);

	CDBG("%s:%d ir_led sd name = %s", __func__, __LINE__,
		ir_led_ctrl->msm_sd.sd.entity.name);
	msm_ir_led_v4l2_subdev_fops = v4l2_subdev_fops;
#ifdef CONFIG_COMPAT
	msm_ir_led_v4l2_subdev_fops.compat_ioctl32 =
		msm_ir_led_subdev_fops_ioctl;
#endif
	ir_led_ctrl->msm_sd.sd.devnode->fops = &msm_ir_led_v4l2_subdev_fops;

	CDBG("probe success\n");
	return rc;
}

MODULE_DEVICE_TABLE(of, msm_ir_led_dt_match);

static struct platform_driver msm_ir_led_platform_driver = {
	.probe = msm_ir_led_platform_probe,
	.driver = {
		.name = "qcom,ir-led",
		.owner = THIS_MODULE,
		.of_match_table = msm_ir_led_dt_match,
	},
};

static int __init msm_ir_led_init_module(void)
{
	int32_t rc = 0;
	CDBG("Enter\n");
	rc = platform_driver_register(&msm_ir_led_platform_driver);
	if (!rc)
		return rc;

	pr_err("platform probe for ir_led failed");

	return rc;
}

static void __exit msm_ir_led_exit_module(void)
{
	platform_driver_unregister(&msm_ir_led_platform_driver);
}

static struct msm_ir_led_table msm_gpio_ir_led_table = {
	.ir_led_driver_type = IR_LED_DRIVER_GPIO,
	.func_tbl = {
		.camera_ir_led_init = msm_ir_led_init,
		.camera_ir_led_release = msm_ir_led_release,
		.camera_ir_led_off = msm_ir_led_off,
		.camera_ir_led_on = msm_ir_led_on,
	},
};

module_init(msm_ir_led_init_module);
module_exit(msm_ir_led_exit_module);
MODULE_DESCRIPTION("MSM IR LED");
MODULE_LICENSE("GPL v2");
