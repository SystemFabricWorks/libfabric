/*
 * Copyright (c) 2013-2015 Intel Corporation, Inc.  All rights reserved.
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


#define VERBS_CM_DATA_SIZE 56
#define VERBS_RESOLVE_TIMEOUT 2000	// ms


static int
fi_ibv_msg_ep_getopt(fid_t fid, int level, int optname,
		  void *optval, size_t *optlen)
{
	switch (level) {
	case FI_OPT_ENDPOINT:
		switch (optname) {
		case FI_OPT_CM_DATA_SIZE:
			if (*optlen < sizeof(size_t))
				return -FI_ETOOSMALL;
			*((size_t *) optval) = VERBS_CM_DATA_SIZE;
			*optlen = sizeof(size_t);
			return 0;
		default:
			return -FI_ENOPROTOOPT;
		}
	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

static int
fi_ibv_msg_ep_setopt(fid_t fid, int level, int optname,
		  const void *optval, size_t optlen)
{
	switch (level) {
	case FI_OPT_ENDPOINT:
		return -FI_ENOPROTOOPT;
	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

static struct fi_ops_ep fi_ibv_msg_ep_base_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = fi_no_cancel,
	.getopt = fi_ibv_msg_ep_getopt,
	.setopt = fi_ibv_msg_ep_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

static struct fi_ibv_msg_ep *fi_ibv_alloc_msg_ep(struct fi_info *info)
{
	struct fi_ibv_msg_ep *ep;

	ep = calloc(1, sizeof *ep);
	if (!ep)
		return NULL;

	ep->info = fi_dupinfo(info);
	if (!ep->info)
		goto err;

	return ep;
err:
	free(ep);
	return NULL;
}

static void fi_ibv_free_msg_ep(struct fi_ibv_msg_ep *ep)
{
	fi_freeinfo(ep->info);
	free(ep);
}

static int fi_ibv_msg_ep_close(fid_t fid)
{
	struct fi_ibv_msg_ep *ep;

	ep = container_of(fid, struct fi_ibv_msg_ep, ep_fid.fid);
	rdma_destroy_ep(ep->id);

	fi_ibv_cleanup_cq(ep);

	VERBS_INFO(FI_LOG_DOMAIN, "EP %p was closed \n", ep);

	fi_ibv_free_msg_ep(ep);

	return 0;
}

static int fi_ibv_msg_ep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct fi_ibv_msg_ep *ep;
	int ret;

	ep = container_of(fid, struct fi_ibv_msg_ep, ep_fid.fid);
	ret = ofi_ep_bind_valid(&fi_ibv_prov, bfid, flags);
	if (ret)
		return ret;

	switch (bfid->fclass) {
	case FI_CLASS_CQ:
		/* Must bind a CQ to either RECV or SEND completions, and
		 * the FI_SELECTIVE_COMPLETION flag is only valid when binding the
		 * FI_SEND CQ. */
		if (!(flags & (FI_RECV|FI_SEND))
				|| (flags & (FI_SEND|FI_SELECTIVE_COMPLETION))
							== FI_SELECTIVE_COMPLETION) {
			return -EINVAL;
		}
		if (flags & FI_RECV) {
			if (ep->rcq)
				return -EINVAL;
			ep->rcq = container_of(bfid, struct fi_ibv_cq, cq_fid.fid);
		}
		if (flags & FI_SEND) {
			if (ep->scq)
				return -EINVAL;
			ep->scq = container_of(bfid, struct fi_ibv_cq, cq_fid.fid);
			if (flags & FI_SELECTIVE_COMPLETION)
				ep->ep_flags |= FI_SELECTIVE_COMPLETION;
			else
				ep->info->tx_attr->op_flags |= FI_COMPLETION;
			ep->ep_id = ep->scq->send_signal_wr_id | ep->scq->ep_cnt++;
		}
		break;
	case FI_CLASS_EQ:
		ep->eq = container_of(bfid, struct fi_ibv_eq, eq_fid.fid);
		ret = rdma_migrate_id(ep->id, ep->eq->channel);
		if (ret)
			return -errno;
		break;
	case FI_CLASS_SRX_CTX:
		ep->srq_ep = container_of(bfid, struct fi_ibv_srq_ep, ep_fid.fid);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int fi_ibv_msg_ep_enable(struct fid_ep *ep_fid)
{
	struct ibv_qp_init_attr attr = { 0 };
	struct fi_ibv_msg_ep *ep;
	struct ibv_pd *pd;
	int ret;

	ep = container_of(ep_fid, struct fi_ibv_msg_ep, ep_fid);
	if (!ep->eq) {
		VERBS_WARN(FI_LOG_EP_CTRL,
			   "Endpoint is not bound to an event queue\n");
		return -FI_ENOEQ;
	}

	if (!ep->scq && !ep->rcq) {
		VERBS_WARN(FI_LOG_EP_CTRL, "Endpoint is not bound to "
			   "a send or receive completion queue\n");
		return -FI_ENOCQ;
	}

	if (!ep->scq && (ofi_send_allowed(ep->info->caps) ||
				ofi_rma_initiate_allowed(ep->info->caps))) {
		VERBS_WARN(FI_LOG_EP_CTRL, "Endpoint is not bound to "
			   "a send completion queue when it has transmit "
			   "capabilities enabled (FI_SEND | FI_RMA).\n");
		return -FI_ENOCQ;
	}

	if (!ep->rcq && ofi_recv_allowed(ep->info->caps)) {
		VERBS_WARN(FI_LOG_EP_CTRL, "Endpoint is not bound to "
			   "a receive completion queue when it has receive "
			   "capabilities enabled. (FI_RECV)\n");
		return -FI_ENOCQ;
	}

	if (ep->scq) {
		attr.cap.max_send_wr = ep->info->tx_attr->size;
		attr.cap.max_send_sge = ep->info->tx_attr->iov_limit;
		attr.send_cq = ep->scq->cq;
		pd = ep->scq->domain->pd;
	} else {
		attr.send_cq = ep->rcq->cq;
		pd = ep->rcq->domain->pd;
	}

	if (ep->rcq) {
		attr.cap.max_recv_wr = ep->info->rx_attr->size;
		attr.cap.max_recv_sge = ep->info->rx_attr->iov_limit;
		attr.recv_cq = ep->rcq->cq;
	} else {
		attr.recv_cq = ep->scq->cq;
	}

	attr.cap.max_inline_data = ep->info->tx_attr->inject_size;

	if (ep->srq_ep) {
		attr.srq = ep->srq_ep->srq;
		/* Use of SRQ, no need to allocate recv_wr entries in the QP */
		attr.cap.max_recv_wr = 0;

		/* Override the default ops to prevent the user from posting WRs to a
		 * QP where a SRQ is attached to */
		ep->ep_fid.msg = &fi_ibv_msg_srq_ep_msg_ops;
	}

	attr.qp_type = IBV_QPT_RC;
	attr.sq_sig_all = 0;
	attr.qp_context = ep;

	ret = rdma_create_qp(ep->id, pd, &attr);
	if (ret) {
		ret = -errno;
		VERBS_WARN(FI_LOG_EP_CTRL, "Unable to create rdma qp: %s (%d)\n",
			   fi_strerror(-ret), -ret);
		return ret;
	}
	return 0;
}

static int fi_ibv_msg_ep_control(struct fid *fid, int command, void *arg)
{
	struct fid_ep *ep;

	switch (fid->fclass) {
	case FI_CLASS_EP:
		ep = container_of(fid, struct fid_ep, fid);
		switch (command) {
		case FI_ENABLE:
			return fi_ibv_msg_ep_enable(ep);
			break;
		default:
			return -FI_ENOSYS;
		}
		break;
	default:
		return -FI_ENOSYS;
	}
}

static struct fi_ops fi_ibv_msg_ep_ops = {
	.size = sizeof(struct fi_ops),
	.close = fi_ibv_msg_ep_close,
	.bind = fi_ibv_msg_ep_bind,
	.control = fi_ibv_msg_ep_control,
	.ops_open = fi_no_ops_open,
};

int fi_ibv_open_ep(struct fid_domain *domain, struct fi_info *info,
		   struct fid_ep **ep_fid, void *context)
{
	struct fi_ibv_domain *dom;
	struct fi_ibv_msg_ep *ep;
	struct fi_ibv_connreq *connreq;
	struct fi_ibv_pep *pep;
	struct fi_info *fi;
	int ret;

	dom = container_of(domain, struct fi_ibv_domain,
			   util_domain.domain_fid);
	if (strcmp(dom->verbs->device->name, info->domain_attr->name)) {
		VERBS_INFO(FI_LOG_DOMAIN, "Invalid info->domain_attr->name\n");
		return -FI_EINVAL;
	}

	fi = dom->info;

	if (info->ep_attr) {
		ret = fi_ibv_check_ep_attr(info, fi);
		if (ret)
			return ret;
	}

	if (info->tx_attr) {
		ret = ofi_check_tx_attr(&fi_ibv_prov, fi->tx_attr,
					info->tx_attr, info->mode);
		if (ret)
			return ret;
	}

	if (info->rx_attr) {
		ret = fi_ibv_check_rx_attr(info->rx_attr, info, fi);
		if (ret)
			return ret;
	}

	ep = fi_ibv_alloc_msg_ep(info);
	if (!ep)
		return -FI_ENOMEM;

	if (!info->handle) {
		ret = fi_ibv_create_ep(NULL, NULL, 0, info, NULL, &ep->id);
		if (ret)
			goto err1;
	} else if (info->handle->fclass == FI_CLASS_CONNREQ) {
		connreq = container_of(info->handle, struct fi_ibv_connreq, handle);
		ep->id = connreq->id;
        } else if (info->handle->fclass == FI_CLASS_PEP) {
		pep = container_of(info->handle, struct fi_ibv_pep, pep_fid.fid);
		ep->id = pep->id;
		pep->id = NULL;

		if (rdma_resolve_addr(ep->id, info->src_addr, info->dest_addr,
				      VERBS_RESOLVE_TIMEOUT)) {
			ret = -errno;
			VERBS_INFO(FI_LOG_DOMAIN, "Unable to rdma_resolve_addr\n");
			goto err2;
		}

		if (rdma_resolve_route(ep->id, VERBS_RESOLVE_TIMEOUT)) {
			ret = -errno;
			VERBS_INFO(FI_LOG_DOMAIN, "Unable to rdma_resolve_route\n");
			goto err2;
		}
	} else {
		ret = -FI_ENOSYS;
		goto err1;
	}

	fastlock_init(&ep->wre_lock);
	ret = util_buf_pool_create(&ep->wre_pool, sizeof(struct fi_ibv_wre),
				   16, 0, VERBS_WRE_CNT);
	if (ret) {
		VERBS_WARN(FI_LOG_CQ, "Failed to create wre_pool\n");
		goto err3;
	}
	dlist_init(&ep->wre_list);

	ep->id->context = &ep->ep_fid.fid;
	ep->ep_fid.fid.fclass = FI_CLASS_EP;
	ep->ep_fid.fid.context = context;
	ep->ep_fid.fid.ops = &fi_ibv_msg_ep_ops;
	ep->ep_fid.ops = &fi_ibv_msg_ep_base_ops;
	ep->ep_fid.msg = &fi_ibv_msg_ep_msg_ops;
	ep->ep_fid.cm = &fi_ibv_msg_ep_cm_ops;
	ep->ep_fid.rma = &fi_ibv_msg_ep_rma_ops;
	ep->ep_fid.atomic = &fi_ibv_msg_ep_atomic_ops;

	ofi_atomic_initialize32(&ep->unsignaled_send_cnt, 0);
	ofi_atomic_initialize32(&ep->comp_pending, 0);
	/* The `send_signal_thr` and `send_comp_thr` values are necessary to avoid
	 * overrun the send queue size */
	/* A signaled Send Request must be posted when the `send_signal_thr`
	 * value is reached */
	ep->send_signal_thr = (ep->info->tx_attr->size * 4) / 5;
	/* Polling of CQ for internal signaled Send Requests must be initiated upon
	 * reaching the `send_comp_thr` value */
	ep->send_comp_thr = (ep->info->tx_attr->size * 9) / 10;

	ep->domain = dom;
	*ep_fid = &ep->ep_fid;

	return FI_SUCCESS;
err3:
	fastlock_destroy(&ep->wre_lock);
err2:
	rdma_destroy_ep(ep->id);
err1:
	fi_ibv_free_msg_ep(ep);
	return ret;
}

static int fi_ibv_pep_bind(fid_t fid, struct fid *bfid, uint64_t flags)
{
	struct fi_ibv_pep *pep;
	int ret;

	pep = container_of(fid, struct fi_ibv_pep, pep_fid.fid);
	if (bfid->fclass != FI_CLASS_EQ)
		return -FI_EINVAL;

	pep->eq = container_of(bfid, struct fi_ibv_eq, eq_fid.fid);
	ret = rdma_migrate_id(pep->id, pep->eq->channel);
	if (ret)
		return -errno;

	return 0;
}

static int fi_ibv_pep_control(struct fid *fid, int command, void *arg)
{
	struct fi_ibv_pep *pep;
	int ret = 0;

	switch (fid->fclass) {
	case FI_CLASS_PEP:
		pep = container_of(fid, struct fi_ibv_pep, pep_fid.fid);
		switch (command) {
		case FI_BACKLOG:
			if (!arg)
				return -FI_EINVAL;
			pep->backlog = *(int *) arg;
			break;
		default:
			ret = -FI_ENOSYS;
			break;
		}
		break;
	default:
		ret = -FI_ENOSYS;
		break;
	}

	return ret;
}

static int fi_ibv_pep_close(fid_t fid)
{
	struct fi_ibv_pep *pep;

	pep = container_of(fid, struct fi_ibv_pep, pep_fid.fid);
	if (pep->id)
		rdma_destroy_ep(pep->id);

	fi_freeinfo(pep->info);
	free(pep);
	return 0;
}

static struct fi_ops fi_ibv_pep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = fi_ibv_pep_close,
	.bind = fi_ibv_pep_bind,
	.control = fi_ibv_pep_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_ep fi_ibv_pep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.getopt = fi_ibv_msg_ep_getopt,
	.setopt = fi_no_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

int fi_ibv_passive_ep(struct fid_fabric *fabric, struct fi_info *info,
		      struct fid_pep **pep, void *context)
{
	struct fi_ibv_pep *_pep;
	int ret;

	_pep = calloc(1, sizeof *_pep);
	if (!_pep)
		return -FI_ENOMEM;

	if (!(_pep->info = fi_dupinfo(info))) {
		ret = -FI_ENOMEM;
		goto err1;
	}

	ret = rdma_create_id(NULL, &_pep->id, &_pep->pep_fid.fid, RDMA_PS_TCP);
	if (ret) {
		VERBS_INFO(FI_LOG_DOMAIN, "Unable to create rdma_cm_id\n");
		goto err2;
	}

	if (info->src_addr) {
		ret = rdma_bind_addr(_pep->id, (struct sockaddr *)info->src_addr);
		if (ret) {
			VERBS_INFO(FI_LOG_DOMAIN, "Unable to bind address to rdma_cm_id\n");
			goto err3;
		}
		_pep->bound = 1;
	}

	_pep->pep_fid.fid.fclass = FI_CLASS_PEP;
	_pep->pep_fid.fid.context = context;
	_pep->pep_fid.fid.ops = &fi_ibv_pep_fi_ops;
	_pep->pep_fid.ops = &fi_ibv_pep_ops;
	_pep->pep_fid.cm = fi_ibv_pep_ops_cm(_pep);

	_pep->src_addrlen = info->src_addrlen;

	*pep = &_pep->pep_fid;
	return 0;

err3:
	rdma_destroy_id(_pep->id);
err2:
	fi_freeinfo(_pep->info);
err1:
	free(_pep);
	return ret;
}

