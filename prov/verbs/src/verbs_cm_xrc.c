/*
 * Copyright (c) 2018 Cray Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "config.h"
#include "fi_verbs.h"

#ifdef INCLUDE_VERBS_XRC
void fi_ibv_save_priv_data(struct fi_ibv_ep *ep, const void *data, size_t len)
{
	ep->conn_setup->event_len = MIN(sizeof(ep->conn_setup->event_data),
					len);
	memcpy(ep->conn_setup->event_data, data, ep->conn_setup->event_len);
}

void fi_ibv_set_xrc_cm_data(struct fi_ibv_xrc_cm_data *local, int reciprocal,
			    uint32_t tag, uint16_t port, uint32_t param)
{
	local->version = FI_IBV_XRC_VERSION;
	local->reciprocal = reciprocal ? 1 : 0;
	local->port = htons(port);
	local->tag = htonl(tag);
	local->param = htonl(param);
}

int fi_ibv_verify_xrc_cm_data(struct fi_ibv_xrc_cm_data *remote,
			      int private_data_len)
{
	if (sizeof(*remote) > private_data_len) {
		VERBS_WARN(FI_LOG_EP_CTRL,
			   "XRC MSG EP CM data length mismatch\n");
		return -FI_EINVAL;
	}

	if (remote->version != FI_IBV_XRC_VERSION) {
		VERBS_WARN(FI_LOG_EP_CTRL,
			   "XRC MSG EP connection protocol mismatch "
			   "(local %"PRIu8", remote %"PRIu8")\n",
			   FI_IBV_XRC_VERSION, remote->version);
		return -FI_EINVAL;
	}
	return FI_SUCCESS;
}

#if ENABLE_DEBUG
void fi_ibv_log_ep_conn(struct fi_ibv_ep *ep, char *desc)
{
	struct sockaddr *src_addr, *dst_addr;

	VERBS_DBG(FI_LOG_FABRIC, "EP %p, %s\n", ep, desc);
	VERBS_DBG(FI_LOG_FABRIC,
		  "EP %p, CM ID %p, TGT CM ID %p, SRQN %d Peer SRQN %d\n",
		  ep, ep->id, ep->tgt_id, ep->srqn, ep->peer_srqn);

	assert(ep->id);

	src_addr = rdma_get_local_addr(ep->id);
	if (src_addr) {
		VERBS_DBG(FI_LOG_FABRIC, "EP %p src_addr: %s:%d\n", ep,
			inet_ntoa(((struct sockaddr_in *)src_addr)->sin_addr),
			ntohs(((struct sockaddr_in *)src_addr)->sin_port));
	}
	dst_addr = rdma_get_peer_addr(ep->id);
	if (dst_addr) {
		VERBS_DBG(FI_LOG_FABRIC, "EP %p dst_addr: %s:%d\n", ep,
			inet_ntoa(((struct sockaddr_in *)dst_addr)->sin_addr),
			ntohs(((struct sockaddr_in *)dst_addr)->sin_port));
	}

	if (ep->ibv_qp) {
		VERBS_DBG(FI_LOG_FABRIC, "EP %p, INI QP Num %d\n",
			  ep, ep->ibv_qp->qp_num);
		VERBS_DBG(FI_LOG_FABRIC, "EP %p, Remote TGT QP Num %d\n", ep,
			  ep->ini_conn->tgt_qpn);
	}
	if (ep->tgt_ibv_qp)
		VERBS_DBG(FI_LOG_FABRIC, "EP %p, TGT QP Num %d\n",
			  ep, ep->tgt_ibv_qp->qp_num);
	if (ep->conn_setup && ep->conn_setup->rsvd_ini_qpn)
		VERBS_DBG(FI_LOG_FABRIC, "EP %p, Reserved INI QPN %d\n",
			  ep, ep->conn_setup->rsvd_ini_qpn->qp_num);
	if (ep->conn_setup && ep->conn_setup->rsvd_tgt_qpn)
		VERBS_DBG(FI_LOG_FABRIC, "EP %p, Reserved TGT QPN %d\n",
			  ep, ep->conn_setup->rsvd_tgt_qpn->qp_num);
}
#endif

void fi_ibv_free_xrc_conn_setup(struct fi_ibv_ep *ep)
{
	assert(ep->conn_setup);

	if (ep->conn_setup->rsvd_ini_qpn)
		fi_ibv_release_qpn(ep->conn_setup->rsvd_ini_qpn);
	if (ep->conn_setup->rsvd_tgt_qpn)
		fi_ibv_release_qpn(ep->conn_setup->rsvd_tgt_qpn);

	free(ep->conn_setup);
	ep->conn_setup = NULL;

	/*Free RDMA CM IDs releasing their associated resources, RDMA CM
	 * is used for connection setup only with XRC */
	if (ep->id) {
		rdma_destroy_id(ep->id);
		ep->id = NULL;
	}
	if (ep->tgt_id) {
		rdma_destroy_id(ep->tgt_id);
		ep->tgt_id = NULL;
	}
}

int fi_ibv_connect_xrc(struct fi_ibv_ep *ep, struct sockaddr *addr,
		       int reciprocal, void *param, size_t paramlen)
{
	struct fi_ibv_domain *domain = fi_ibv_msg_ep_to_domain(ep);
	struct sockaddr *src_addr, *dst_addr;
	int ret;

	assert(ep->id && !ep->ibv_qp && !ep->ini_conn);

	src_addr = rdma_get_local_addr(ep->id);
	if (src_addr) {
		VERBS_DBG(FI_LOG_FABRIC, "XRC connect src_addr: %s:%d\n",
			inet_ntoa(((struct sockaddr_in *)src_addr)->sin_addr),
			ntohs(((struct sockaddr_in *)src_addr)->sin_port));
	}
	dst_addr = rdma_get_peer_addr(ep->id);
	if (dst_addr) {
		VERBS_DBG(FI_LOG_FABRIC, "XRC connect dst_addr: %s:%d\n",
			  inet_ntoa(((struct sockaddr_in *)dst_addr)->sin_addr),
			  ntohs(((struct sockaddr_in *)dst_addr)->sin_port));
	}

	if (!reciprocal) {
		ep->conn_setup = calloc(1, sizeof(*ep->conn_setup));
		if (!ep)
			return -FI_ENOMEM;
	}

	fastlock_acquire(&domain->xrc.ini_mgmt_lock);
	ep->ini_conn = fi_ibv_get_shared_ini_conn(ep);
	if (!ep->ini_conn) {
		ret = -errno;
		VERBS_WARN(FI_LOG_FABRIC,
			   "Get of shared XRC INI connection failed %d\n", ret);
		fastlock_release(&domain->xrc.ini_mgmt_lock);
		if (!reciprocal) {
			free(ep->conn_setup);
			ep->conn_setup = NULL;
		}
		return ret;
	}
	fi_ibv_add_pending_ini_conn(ep, reciprocal, param, paramlen);
	fi_ibv_sched_ini_conn(ep->ini_conn);
	fastlock_release(&domain->xrc.ini_mgmt_lock);

	return FI_SUCCESS;
}

void fi_ibv_ep_ini_conn_done(struct fi_ibv_ep *ep, uint32_t peer_srqn,
			     uint32_t tgt_qpn)
{
	struct fi_ibv_domain *domain = fi_ibv_msg_ep_to_domain(ep);

	assert(ep->id && ep->ini_conn);

	fastlock_acquire(&domain->xrc.ini_mgmt_lock);
#if ENABLE_DEBUG
	fi_ibv_log_ep_conn(ep, "INI Connection Done");
#endif
	assert(ep->ini_conn->state == FI_IBV_INI_QP_CONNECTING ||
	       ep->ini_conn->state == FI_IBV_INI_QP_CONNECTED);

	/* If this was a physical INI/TGT QP connection, remove the QP
	 * from control of the RDMA CM. We don't want the shared INI QP
	 * to be destroyed if this endpoint closes. */
	if (ep->id->qp) {
		ep->ini_conn->state = FI_IBV_INI_QP_CONNECTED;
		ep->ini_conn->tgt_qpn = tgt_qpn;
		ep->id->qp = NULL;
		VERBS_DBG(FI_LOG_EP_CTRL,
			  "Set INI Conn QP %d remote TGT QP %d\n",
			  ep->ini_conn->ini_qp->qp_num,
			  ep->ini_conn->tgt_qpn);
	}

	fi_ibv_sched_ini_conn(ep->ini_conn);
	fastlock_release(&domain->xrc.ini_mgmt_lock);
}

void fi_ibv_ep_ini_conn_rejected(struct fi_ibv_ep *ep)
{
	struct fi_ibv_domain *domain = fi_ibv_msg_ep_to_domain(ep);

	assert(ep->id && ep->ini_conn);

	fastlock_acquire(&domain->xrc.ini_mgmt_lock);
#if ENABLE_DEBUG
	fi_ibv_log_ep_conn(ep, "INI Connection Rejected");
#endif
	fi_ibv_put_shared_ini_conn(ep);
	fastlock_release(&domain->xrc.ini_mgmt_lock);
}

void fi_ibv_ep_tgt_conn_done(struct fi_ibv_ep *ep)
{
#if ENABLE_DEBUG
	fi_ibv_log_ep_conn(ep, "TGT Connection Done\n");
#endif
	if (ep->tgt_id->qp) {
		assert(ep->tgt_ibv_qp == ep->tgt_id->qp);
		ep->tgt_id->qp = NULL;
	}
}

int fi_ibv_accept_xrc(struct fi_ibv_ep *ep, int reciprocal,
		      void *param, size_t paramlen)
{
	struct sockaddr *src_addr, *dst_addr;
	struct fi_ibv_connreq *connreq;
	struct rdma_conn_param conn_param = { 0 };
	struct fi_ibv_xrc_cm_data *cm_data = param;
	int ret;

	src_addr = rdma_get_local_addr(ep->tgt_id);
	if (src_addr) {
		VERBS_INFO(FI_LOG_CORE, "src_addr: %s:%d\n",
			inet_ntoa(((struct sockaddr_in *)src_addr)->sin_addr),
			ntohs(((struct sockaddr_in *)src_addr)->sin_port));
	}
	dst_addr = rdma_get_peer_addr(ep->tgt_id);
	if (dst_addr) {
		VERBS_INFO(FI_LOG_CORE, "dst_addr: %s:%d\n",
			inet_ntoa(((struct sockaddr_in *)dst_addr)->sin_addr),
			ntohs(((struct sockaddr_in *)dst_addr)->sin_port));
	}

	connreq = container_of(ep->info->handle, struct fi_ibv_connreq,
			       handle);
	ret = fi_ibv_ep_create_tgt_qp(ep, connreq->xrc.conn_data);
	if (ret)
		return ret;

	fi_ibv_set_xrc_cm_data(cm_data, connreq->xrc.is_reciprocal,
			       connreq->xrc.conn_tag, connreq->xrc.port,
			       ep->srqn);
	conn_param.private_data = cm_data;
	conn_param.private_data_len = paramlen;
	conn_param.responder_resources = RDMA_MAX_RESP_RES;
	conn_param.initiator_depth = RDMA_MAX_INIT_DEPTH;
	conn_param.flow_control = 1;
	conn_param.rnr_retry_count = 7;
	if (ep->srq_ep)
		conn_param.srq = 1;

	/* Shared INI/TGT QP connection use a temporarily reserved QP number
	 * avoid the appearance of being a stale/duplicate IB CM message */
	if (!ep->tgt_id->qp)
		conn_param.qp_num = ep->conn_setup->rsvd_tgt_qpn->qp_num;

	if (connreq->xrc.is_reciprocal)
		fi_ibv_eq_clear_xrc_conn_tag(ep);
	else
		ep->conn_setup->tag = connreq->xrc.conn_tag;

	assert(ep->conn_state == FI_IBV_XRC_UNCONNECTED ||
	       ep->conn_state == FI_IBV_XRC_ORIG_CONNECTED);
	ep->conn_state++;

	ret = rdma_accept(ep->tgt_id, &conn_param);
	if (ret) {
		ret = -errno;
		VERBS_INFO_ERRNO(FI_LOG_EP_CTRL,
				 "XRC TGT, ibv_open_qp", errno);
		ep->conn_state--;
	}
	free(connreq);
	return ret;
}

int fi_ibv_process_xrc_connreq(struct fi_ibv_ep *ep,
			       struct fi_ibv_connreq *connreq)
{
	int ret;

	assert(ep->info->src_addr);
	assert(ep->info->dest_addr);

	ep->conn_setup = calloc(1, sizeof(*ep->conn_setup));
	if (!ep->conn_setup)
		return -FI_ENOMEM;

	/* This endpoint was created on the passive side of a connection
	 * request. The connection information will be for the target QP. */
	ep->tgt_info = fi_dupinfo(ep->info);
	if (!ep->tgt_info) {
		ret = -FI_ENOMEM;
		goto dup_err;
	}

	/* The reciprocal connection request will go back to the passive
	 * port indicated by the active side */
	if (((struct sockaddr *)ep->info->src_addr)->sa_family == AF_INET) {
		((struct sockaddr_in *)(ep->info->src_addr))->sin_port = 0;
		((struct sockaddr_in *)(ep->info->dest_addr))->sin_port =
						htons(connreq->xrc.port);
	} else if (((struct sockaddr *)ep->info->src_addr)->sa_family ==
								AF_INET6) {
		((struct sockaddr_in6 *)(ep->info->src_addr))->sin6_port = 0;
		((struct sockaddr_in6 *)(ep->info->dest_addr))->sin6_port =
						htons(connreq->xrc.port);
	} else
		assert(0);

	ret = fi_ibv_create_ep(NULL, NULL, 0, ep->info, NULL, &ep->id);
	if (ret) {
		VERBS_WARN(FI_LOG_EP_CTRL,
			   "Creation of INI cm_id failed %d\n", ret);
		goto create_err;
	}
	ep->tgt_id = connreq->id;
	ep->tgt_id->context = &ep->util_ep.ep_fid.fid;

	return FI_SUCCESS;

create_err:
	fi_freeinfo(ep->tgt_info);
	ep->tgt_info = NULL;
dup_err:
	free(ep->conn_setup);
	return ret;
}

int fi_ibv_process_xrc_recip_connreq(struct fi_ibv_eq *eq,
				     struct fi_ibv_connreq *connreq,
				     struct fi_eq_cm_entry *entry)
{
	struct fi_ibv_ep *ep;
	struct fi_ibv_xrc_cm_data xrc_cm_data;
	size_t xrc_cm_datalen;
	int ret;

	ep = fi_ibv_eq_xrc_conn_tag2ep(eq, connreq->xrc.conn_tag);
	if (!ep)
		return -FI_EINVAL;

	ep->tgt_id = connreq->id;
	ep->tgt_info = fi_dupinfo(entry->info);
	if (!ep->tgt_info) {
		VERBS_WARN(FI_LOG_FABRIC, "fi_dupinfo for TGT failed\n");
		return -FI_EINVAL;
	}
	ep->tgt_id->context = &ep->util_ep.ep_fid.fid;
	ep->info->handle = entry->info->handle;

	ret = rdma_migrate_id(ep->tgt_id, ep->eq->channel);
	if (ret) {
		ret = -errno;
		VERBS_WARN(FI_LOG_FABRIC, "Could not migrate XRC tgt_id %d\n",
			   ret);
		goto err;
	}

	xrc_cm_datalen = sizeof(xrc_cm_data);
	ret = fi_ibv_accept_xrc(ep, FI_IBV_RECIP_CONN, &xrc_cm_data,
				xrc_cm_datalen);
	if (ret) {
		VERBS_WARN(FI_LOG_FABRIC,
			   "Reciprocal XRC Accept failed %d\n", ret);
		goto err;
	}
	return -FI_EAGAIN;

err:
	fi_freeinfo(ep->tgt_info);
	ep->tgt_info = NULL;
	return -FI_EAGAIN;
}

#else /* INCLUDE_VERBS_XRC */

void fi_ibv_set_xrc_cm_data(struct fi_ibv_xrc_cm_data *local, int reciprocal,
			    uint32_t tag, uint16_t port, uint32_t param)
{
	/* Code error if this function is called with XRC disabled */
	assert(0);
}

int fi_ibv_verify_xrc_cm_data(struct fi_ibv_xrc_cm_data *remote,
			      int private_data_len)
{
	/* Code error if this function is called with XRC disabled */
	assert(0);
	return -FI_ENOSYS;
}

int fi_ibv_connect_xrc(struct fi_ibv_ep *ep, struct sockaddr *addr,
		       int reciprocal, void *param, size_t paramlen)
{
	/* Code error if this function is called with XRC disabled */
	assert(0);
	return -FI_ENOSYS;
}

int fi_ibv_accept_xrc(struct fi_ibv_ep *ep, int reciprocal,
		      void *param, size_t paramlen)
{
	/* Code error if this function is called with XRC disabled */
	assert(0);
	return -FI_ENOSYS;
}

int fi_ibv_process_xrc_connreq(struct fi_ibv_ep *ep,
			       struct fi_ibv_connreq *connreq)
{
	/* Code error if this function is called with XRC disabled */
	assert(0);
	return -FI_ENOSYS;
}

#endif /* INCLUDE_VERBS_XRC */
