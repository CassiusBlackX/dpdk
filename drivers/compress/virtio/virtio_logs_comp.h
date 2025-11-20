/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 HUAWEI TECHNOLOGIES CO., LTD.
 */

#ifndef _VIRTIO_LOGS_H_
#define _VIRTIO_LOGS_H_

#include <rte_log.h>

extern int virtio_comp_logtype_init;
#define RTE_LOGTYPE_VIRTIO_COMP_INIT virtio_comp_logtype_init

#define PMD_INIT_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, VIRTIO_COMP_INIT, "%s(): ", __func__, __VA_ARGS__)

#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

extern int virtio_comp_logtype_driver;
#define RTE_LOGTYPE_VIRTIO_COMP_DRIVER virtio_comp_logtype_driver
#define PMD_DRV_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, VIRTIO_COMP_DRIVER, "%s(): ", __func__, __VA_ARGS__)

#define VIRTIO_COMP_INIT_LOG_IMPL(level, ...) \
	RTE_LOG_LINE_PREFIX(level, VIRTIO_COMP_INIT, "%s(): ", __func__, __VA_ARGS__)

#define VIRTIO_COMP_INIT_LOG_INFO(fmt, ...) \
	VIRTIO_COMP_INIT_LOG_IMPL(INFO, fmt, ## __VA_ARGS__)

#define VIRTIO_COMP_INIT_LOG_DBG(fmt, ...) \
	VIRTIO_COMP_INIT_LOG_IMPL(DEBUG, fmt, ## __VA_ARGS__)

#define VIRTIO_COMP_INIT_LOG_ERR(fmt, ...) \
	VIRTIO_COMP_INIT_LOG_IMPL(ERR, fmt, ## __VA_ARGS__)

extern int virtio_comp_logtype_session;
#define RTE_LOGTYPE_VIRTIO_COMP_SESSION virtio_comp_logtype_session

#define VIRTIO_COMP_SESSION_LOG_IMPL(level, ...) \
	RTE_LOG_LINE_PREFIX(level, VIRTIO_COMP_SESSION, "%s(): ", __func__, __VA_ARGS__)

#define VIRTIO_COMP_SESSION_LOG_INFO(fmt, ...) \
	VIRTIO_COMP_SESSION_LOG_IMPL(INFO, fmt, ## __VA_ARGS__)

#define VIRTIO_COMP_SESSION_LOG_DBG(fmt, ...) \
	VIRTIO_COMP_SESSION_LOG_IMPL(DEBUG, fmt, ## __VA_ARGS__)

#define VIRTIO_COMP_SESSION_LOG_ERR(fmt, ...) \
	VIRTIO_COMP_SESSION_LOG_IMPL(ERR, fmt, ## __VA_ARGS__)

extern int virtio_comp_logtype_rx;
#define RTE_LOGTYPE_VIRTIO_COMP_RX virtio_comp_logtype_rx

#define VIRTIO_COMP_RX_LOG_IMPL(level, ...) \
	RTE_LOG_LINE_PREFIX(level, VIRTIO_COMP_RX, "%s(): ", __func__, __VA_ARGS__)

#define VIRTIO_COMP_RX_LOG_INFO(fmt, ...) \
	VIRTIO_COMP_RX_LOG_IMPL(INFO, fmt, ## __VA_ARGS__)

#define VIRTIO_COMP_RX_LOG_DBG(fmt, ...) \
	VIRTIO_COMP_RX_LOG_IMPL(DEBUG, fmt, ## __VA_ARGS__)

#define VIRTIO_COMP_RX_LOG_ERR(fmt, ...) \
	VIRTIO_COMP_RX_LOG_IMPL(ERR, fmt, ## __VA_ARGS__)

extern int virtio_comp_logtype_tx;
#define RTE_LOGTYPE_VIRTIO_COMP_TX virtio_comp_logtype_tx

#define VIRTIO_COMP_TX_LOG_IMPL(level, ...) \
	RTE_LOG_LINE_PREFIX(level, VIRTIO_COMP_TX, "%s(): ", __func__, __VA_ARGS__)

#define VIRTIO_COMP_TX_LOG_INFO(fmt, ...) \
	VIRTIO_COMP_TX_LOG_IMPL(INFO, fmt, ## __VA_ARGS__)

#define VIRTIO_COMP_TX_LOG_DBG(fmt, ...) \
	VIRTIO_COMP_TX_LOG_IMPL(DEBUG, fmt, ## __VA_ARGS__)

#define VIRTIO_COMP_TX_LOG_ERR(fmt, ...) \
	VIRTIO_COMP_TX_LOG_IMPL(ERR, fmt, ## __VA_ARGS__)

extern int virtio_comp_logtype_driver;
#define RTE_LOGTYPE_VIRTIO_COMP_DRIVER virtio_comp_logtype_driver

#define VIRTIO_COMP_DRV_LOG_IMPL(level, ...) \
	RTE_LOG_LINE_PREFIX(level, VIRTIO_COMP_DRIVER, "%s(): ", __func__, __VA_ARGS__)

#define VIRTIO_COMP_DRV_LOG_INFO(fmt, ...) \
	VIRTIO_COMP_DRV_LOG_IMPL(INFO, fmt, ## __VA_ARGS__)

#define VIRTIO_COMP_DRV_LOG_DBG(fmt, ...) \
	VIRTIO_COMP_DRV_LOG_IMPL(DEBUG, fmt, ## __VA_ARGS__)

#define VIRTIO_COMP_DRV_LOG_ERR(fmt, ...) \
	VIRTIO_COMP_DRV_LOG_IMPL(ERR, fmt, ## __VA_ARGS__)

#endif /* _VIRTIO_LOGS_H_ */
