/*
 * Copyright (c) 2017 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *	   Redistribution and use in source and binary forms, with or
 *	   without modification, are permitted provided that the following
 *	   conditions are met:
 *
 *		- Redistributions of source code must retain the above
 *		  copyright notice, this list of conditions and the following
 *		  disclaimer.
 *
 *		- Redistributions in binary form must reproduce the above
 *		  copyright notice, this list of conditions and the following
 *		  disclaimer in the documentation and/or other materials
 *		  provided with the distribution.
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

#include <rdma/fi_errno.h>
#include "rdma/fi_eq.h"
#include <prov.h>
#include "tcpx.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <fi_util.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netdb.h>

static ssize_t tcpx_recvmsg(struct fid_ep *ep, const struct fi_msg *msg,
			    uint64_t flags)
{
	struct tcpx_posted_rx *posted_rx;
	struct tcpx_domain *tcpx_domain;
	struct tcpx_ep *tcpx_ep;
	union tcpx_iov iov;
	size_t len;
	int i;

	tcpx_ep = container_of(ep, struct tcpx_ep, util_ep.ep_fid);
	tcpx_domain = container_of(tcpx_ep->util_ep.domain,
				   struct tcpx_domain, util_domain);

	fastlock_acquire(&tcpx_domain->progress.posted_rx_pool_lock);
	posted_rx = util_buf_alloc(tcpx_domain->progress.posted_rx_pool);
	fastlock_release(&tcpx_domain->progress.posted_rx_pool_lock);
	if (!posted_rx)
		return -FI_ENOMEM;

	posted_rx->ep = tcpx_ep;
	posted_rx->flags = flags;
	posted_rx->context = msg->context;
	posted_rx->iov_cnt = msg->iov_count;
	len = 0;

	for (i = 0 ; i < msg->iov_count; i++) {
		iov.iov.addr = (uintptr_t) msg->msg_iov[i].iov_base;
		iov.iov.len = msg->msg_iov[i].iov_len;
		len += msg->msg_iov[i].iov_len;
		memcpy(&posted_rx->iov[i], &iov, sizeof(iov));
	}
	posted_rx->data_len = len;
	pthread_mutex_lock(&tcpx_ep->posted_rx_list_lock);
	dlist_insert_tail(&posted_rx->entry, &tcpx_ep->posted_rx_list);
	pthread_mutex_unlock(&tcpx_ep->posted_rx_list_lock);
	return FI_SUCCESS;
}

static ssize_t tcpx_recv(struct fid_ep *ep, void *buf, size_t len, void *desc,
			 fi_addr_t src_addr, void *context)
{
	struct fi_msg msg;
	struct iovec msg_iov;

	msg_iov.iov_base = buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.addr = src_addr;
	msg.context = context;
	msg.data = 0;

	return tcpx_recvmsg(ep, &msg, 0);
}

static ssize_t tcpx_recvv(struct fid_ep *ep, const struct iovec *iov, void **desc,
			  size_t count, fi_addr_t src_addr, void *context)
{
	struct fi_msg msg;

	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.addr = src_addr;
	msg.context = context;
	msg.data = 0;
	return tcpx_recvmsg(ep, &msg, 0);
}

static ssize_t tcpx_sendmsg(struct fid_ep *ep, const struct fi_msg *msg,
			    uint64_t flags)
{
	struct tcpx_ep *tcpx_ep;
	int ret = FI_SUCCESS;
	uint64_t total_len = 0;
	uint64_t data_len = 0;
	uint8_t op_data;
	struct tcpx_domain *tcpx_domain;
	union tcpx_iov tx_iov;
	int i;

	tcpx_ep = container_of(ep, struct tcpx_ep, util_ep.ep_fid);
	tcpx_domain = container_of(tcpx_ep->util_ep.domain,
				   struct tcpx_domain, util_domain);

	if (msg->iov_count > TCPX_IOV_LIMIT)
		return -FI_EINVAL;

	op_data = TCPX_OP_MSG_SEND;
	total_len += sizeof(op_data);
	total_len += sizeof(msg->iov_count);
	total_len += sizeof(flags);
	total_len += sizeof(msg->context);
	total_len += sizeof(total_len);

	if (flags & FI_REMOTE_CQ_DATA)
		total_len += sizeof(uint64_t);

	for (i = 0; i < msg->iov_count; i++)
		data_len += msg->msg_iov[i].iov_len;

	if (flags & FI_INJECT) {
		if (data_len > TCPX_MAX_INJECT_SZ)
			return -FI_EINVAL;

		total_len += data_len;
	} else {
		total_len += msg->iov_count * sizeof(tx_iov);
	}

	fastlock_acquire(&tcpx_ep->rb_lock);
	if (ofi_rbavail(&tcpx_ep->rb) < total_len) {
		ret = -FI_EAGAIN;
		goto err;
	}

	ofi_rbwrite(&tcpx_ep->rb, &op_data, sizeof(op_data));
	ofi_rbwrite(&tcpx_ep->rb, &msg->iov_count, sizeof(msg->iov_count));
	ofi_rbwrite(&tcpx_ep->rb, &flags, sizeof(flags));
	ofi_rbwrite(&tcpx_ep->rb, &msg->context, sizeof(msg->context));
	ofi_rbwrite(&tcpx_ep->rb, &data_len, sizeof(data_len));

	if (flags & FI_REMOTE_CQ_DATA)
		ofi_rbwrite(&tcpx_ep->rb, &msg->data, sizeof(msg->data));

	if (flags & FI_INJECT) {
		for (i = 0; i < msg->iov_count; i++) {
			ofi_rbwrite(&tcpx_ep->rb, msg->msg_iov[i].iov_base,
				    msg->msg_iov[i].iov_len);
		}
	}else {
		for (i = 0; i < msg->iov_count; i++) {
			tx_iov.iov.addr = (uintptr_t) msg->msg_iov[i].iov_base;
			tx_iov.iov.len = msg->msg_iov[i].iov_len;
			ofi_rbwrite(&tcpx_ep->rb, &tx_iov, sizeof(tx_iov));
		}
	}
	ofi_rbcommit(&tcpx_ep->rb);
	tcpx_progress_signal(&tcpx_domain->progress);
err:
	fastlock_release(&tcpx_ep->rb_lock);
	return ret;
}

static ssize_t tcpx_send(struct fid_ep *ep, const void *buf, size_t len, void *desc,
			 fi_addr_t dest_addr, void *context)
{
	struct fi_msg msg;
	struct iovec msg_iov;

	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.addr = dest_addr;
	msg.context = context;

	return tcpx_sendmsg(ep, &msg, 0);
}

static ssize_t tcpx_sendv(struct fid_ep *ep, const struct iovec *iov, void **desc,
			  size_t count, fi_addr_t dest_addr, void *context)
{
	struct fi_msg msg;

	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.addr = dest_addr;
	msg.context = context;
	return tcpx_sendmsg(ep, &msg, 0);
}


static ssize_t tcpx_inject(struct fid_ep *ep, const void *buf, size_t len,
			   fi_addr_t dest_addr)
{
	struct fi_msg msg;
	struct iovec msg_iov;

	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.iov_count = 1;
	msg.addr = dest_addr;

	return tcpx_sendmsg(ep, &msg, FI_INJECT | TCPX_NO_COMPLETION);
}

static ssize_t tcpx_senddata(struct fid_ep *ep, const void *buf, size_t len, void *desc,
			     uint64_t data, fi_addr_t dest_addr, void *context)
{
	struct fi_msg msg;
	struct iovec msg_iov;

	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;

	msg.msg_iov = &msg_iov;
	msg.desc = NULL;
	msg.iov_count = 1;
	msg.addr = dest_addr;
	msg.context = NULL;
	msg.data = data;

	return tcpx_sendmsg(ep, &msg, FI_REMOTE_CQ_DATA);
}

static ssize_t tcpx_injectdata(struct fid_ep *ep, const void *buf, size_t len,
			       uint64_t data, fi_addr_t dest_addr)
{
	struct fi_msg msg;
	struct iovec msg_iov;

	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;

	msg.msg_iov = &msg_iov;
	msg.desc = NULL;
	msg.iov_count = 1;
	msg.addr = dest_addr;
	msg.context = NULL;
	msg.data = 0;

	return tcpx_sendmsg(ep, &msg, FI_REMOTE_CQ_DATA | FI_INJECT |
			    TCPX_NO_COMPLETION);
}

static struct fi_ops_msg tcpx_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = tcpx_recv,
	.recvv = tcpx_recvv,
	.recvmsg = tcpx_recvmsg,
	.send = tcpx_send,
	.sendv = tcpx_sendv,
	.sendmsg = tcpx_sendmsg,
	.inject = tcpx_inject,
	.senddata = tcpx_senddata,
	.injectdata = tcpx_injectdata,
};

static int tcpx_setup_socket(SOCKET sock)
{
	int ret, optval = 1;

	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (ret) {
		FI_WARN(&tcpx_prov, FI_LOG_EP_CTRL,"setsockopt reuseaddr failed\n");
		return ret;
	}

	ret = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
	if (ret) {
		FI_WARN(&tcpx_prov, FI_LOG_EP_CTRL,"setsockopt nodelay failed\n");
		return ret;
	}

	return ret;
}

static int tcpx_ep_connect(struct fid_ep *ep, const void *addr,
			   const void *param, size_t paramlen)
{
	struct tcpx_ep *tcpx_ep = container_of(ep, struct tcpx_ep, util_ep.ep_fid);
	struct poll_fd_info *fd_info;
	struct util_fabric *util_fabric;
	struct tcpx_fabric *tcpx_fabric;
	int ret;

	util_fabric = tcpx_ep->util_ep.domain->fabric;
	tcpx_fabric = container_of(util_fabric, struct tcpx_fabric, util_fabric);

	if (!addr || !tcpx_ep->conn_fd || paramlen > TCPX_MAX_CM_DATA_SIZE)
		return -FI_EINVAL;

	fd_info = calloc(1, sizeof(*fd_info));
	if (!fd_info) {
		FI_WARN(&tcpx_prov, FI_LOG_EP_CTRL,
			"cannot allocate memory \n");
		return -FI_ENOMEM;
	}

	ret = connect(tcpx_ep->conn_fd, (struct sockaddr *) addr,
		      ofi_sizeofaddr(addr));
	if (ret && errno != FI_EINPROGRESS) {
		free(fd_info);
		return -errno;
	}

	fd_info->fid = &tcpx_ep->util_ep.ep_fid.fid;
	fd_info->flags = POLL_MGR_FREE;
	fd_info->type = CONNECT_SOCK;
	fd_info->state = ESTABLISH_CONN;

	if (paramlen) {
		fd_info->cm_data_sz = paramlen;
		memcpy(fd_info->cm_data, param, paramlen);
	}

	fastlock_acquire(&tcpx_fabric->poll_mgr.lock);
	dlist_insert_tail(&fd_info->entry, &tcpx_fabric->poll_mgr.list);
	fastlock_release(&tcpx_fabric->poll_mgr.lock);
	fd_signal_set(&tcpx_fabric->poll_mgr.signal);
	return 0;
}

static int tcpx_ep_accept(struct fid_ep *ep, const void *param, size_t paramlen)
{
	struct tcpx_ep *tcpx_ep = container_of(ep, struct tcpx_ep, util_ep.ep_fid);
	struct poll_fd_info *fd_info;
	struct util_fabric *util_fabric;
	struct tcpx_fabric *tcpx_fabric;

	util_fabric = tcpx_ep->util_ep.domain->fabric;
	tcpx_fabric = container_of(util_fabric, struct tcpx_fabric, util_fabric);

	if (tcpx_ep->conn_fd == INVALID_SOCKET)
		return -FI_EINVAL;

	fd_info = calloc(1, sizeof(*fd_info));
	if (!fd_info) {
		FI_WARN(&tcpx_prov, FI_LOG_EP_CTRL,
			"cannot allocate memory \n");
		return -FI_ENOMEM;
	}

	fd_info->fid = &tcpx_ep->util_ep.ep_fid.fid;
	fd_info->flags = POLL_MGR_FREE;
	fd_info->type = ACCEPT_SOCK;
	if (paramlen) {
		fd_info->cm_data_sz = paramlen;
		memcpy(fd_info->cm_data, param, paramlen);
	}

	fastlock_acquire(&tcpx_fabric->poll_mgr.lock);
	dlist_insert_tail(&fd_info->entry, &tcpx_fabric->poll_mgr.list);
	fastlock_release(&tcpx_fabric->poll_mgr.lock);
	fd_signal_set(&tcpx_fabric->poll_mgr.signal);
	return 0;
}

static struct fi_ops_cm tcpx_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.setname = fi_no_setname,
	.getname = fi_no_getname,
	.getpeer = fi_no_getpeer,
	.connect = tcpx_ep_connect,
	.listen = fi_no_listen,
	.accept = tcpx_ep_accept,
	.reject = fi_no_reject,
	.shutdown = fi_no_shutdown,
	.join = fi_no_join,
};

static int tcpx_ep_close(struct fid *fid)
{
	struct tcpx_ep *ep;
	struct tcpx_domain *tcpx_domain;

	ep = container_of(fid, struct tcpx_ep, util_ep.ep_fid.fid);
	tcpx_domain = container_of(ep->util_ep.domain,
				   struct tcpx_domain, util_domain);

	tcpx_progress_ep_remove(&tcpx_domain->progress, ep);
	pthread_mutex_destroy(&ep->posted_rx_list_lock);
	fastlock_destroy(&ep->rb_lock);

	ofi_close_socket(ep->conn_fd);
	ofi_endpoint_close(&ep->util_ep);

	free(ep);
	return 0;
}

static int tcpx_ep_ctrl(struct fid *fid, int command, void *arg)
{
	struct tcpx_ep *ep;

	ep = container_of(fid, struct tcpx_ep, util_ep.ep_fid.fid);
	switch (command) {
	case FI_ENABLE:
		if (!ep->util_ep.rx_cq || !ep->util_ep.tx_cq)
			return -FI_ENOCQ;
		break;
	default:
		return -FI_ENOSYS;
	}
	return 0;
}
static int tcpx_ep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct util_ep *util_ep;

	util_ep = container_of(fid, struct util_ep, ep_fid.fid);
	return ofi_ep_bind(util_ep, bfid, flags);
}

static struct fi_ops tcpx_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = tcpx_ep_close,
	.bind = tcpx_ep_bind,
	.control = tcpx_ep_ctrl,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_ep tcpx_ep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = fi_no_cancel,
	.getopt = fi_no_getopt,
	.setopt = fi_no_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

static void tcpx_manual_progress(struct util_ep *util_ep)
{
	return;
}

int tcpx_endpoint(struct fid_domain *domain, struct fi_info *info,
		  struct fid_ep **ep_fid, void *context)
{
	struct tcpx_ep *ep;
	struct tcpx_conn_handle *handle;
	int af, ret;

	ep = calloc(1, sizeof(*ep));
	if (!ep)
		return -FI_ENOMEM;

	ret = ofi_endpoint_init(domain, &tcpx_util_prov, info, &ep->util_ep,
				context, tcpx_manual_progress);
	if (ret)
		goto err1;

	if (info->handle) {
		handle = container_of(info->handle, struct tcpx_conn_handle,
				      handle);
		ep->conn_fd = handle->conn_fd;
		free(handle);
	} else {
		if (info->src_addr)
			af = ((const struct sockaddr *) info->src_addr)->sa_family;
		else if (info->dest_addr)
			af = ((const struct sockaddr *) info->dest_addr)->sa_family;
		else
			af = ofi_get_sa_family(info->addr_format);

		ep->conn_fd = ofi_socket(af, SOCK_STREAM, 0);
		if (ep->conn_fd == INVALID_SOCKET) {
			ret = -errno;
			goto err1;
		}
	}
	ret = tcpx_setup_socket(ep->conn_fd);
	if (ret)
		goto err2;

	dlist_init(&ep->rx_queue);
	dlist_init(&ep->tx_queue);
	dlist_init(&ep->posted_rx_list);
	ret = pthread_mutex_init(&ep->posted_rx_list_lock, NULL);
	if (ret)
		goto err2;

	ret = fastlock_init(&ep->rb_lock);
	if (ret)
		goto err3;

	ret = ofi_rbinit(&ep->rb, TCPX_MAX_EP_RB_SIZE);
	if (ret)
		goto err4;

	*ep_fid = &ep->util_ep.ep_fid;
	(*ep_fid)->fid.ops = &tcpx_ep_fi_ops;
	(*ep_fid)->ops = &tcpx_ep_ops;
	(*ep_fid)->cm = &tcpx_cm_ops;
	(*ep_fid)->msg = &tcpx_msg_ops;

	return 0;
err4:
	fastlock_destroy(&ep->rb_lock);
err3:
	pthread_mutex_destroy(&ep->posted_rx_list_lock);
err2:
	ofi_close_socket(ep->conn_fd);
err1:
	free(ep);
	return ret;
}

static int tcpx_pep_fi_close(struct fid *fid)
{
	struct tcpx_pep *pep;
	struct tcpx_fabric *tcpx_fabric;

	pep = container_of(fid, struct tcpx_pep, util_pep.pep_fid.fid);

	tcpx_fabric = container_of(pep->util_pep.fabric, struct tcpx_fabric,
				   util_fabric);

	/* It's possible to close the PEP before adding completes */
	fastlock_acquire(&tcpx_fabric->poll_mgr.lock);
	pep->poll_info.flags = POLL_MGR_DEL;
	if (pep->poll_info.entry.next == pep->poll_info.entry.prev)
		dlist_insert_tail(&pep->poll_info.entry, &tcpx_fabric->poll_mgr.list);

	fastlock_release(&tcpx_fabric->poll_mgr.lock);
	fd_signal_set(&tcpx_fabric->poll_mgr.signal);

	while (!(pep->poll_info.flags & POLL_MGR_ACK))
		sleep(0);

	ofi_pep_close(&pep->util_pep);
	free(pep);
	return 0;
}

static int tcpx_pep_fi_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct tcpx_pep *tcpx_pep = container_of(fid, struct tcpx_pep,
						 util_pep.pep_fid.fid);

	switch (bfid->fclass) {
	case FI_CLASS_EQ:
		return ofi_pep_bind_eq(&tcpx_pep->util_pep,
				       container_of(bfid, struct util_eq,
						    eq_fid.fid), flags);
	default:
		FI_WARN(&tcpx_prov, FI_LOG_EP_CTRL,
			"invalid FID class for binding\n");
		return -FI_EINVAL;
	}
}

static struct fi_ops tcpx_pep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = tcpx_pep_fi_close,
	.bind = tcpx_pep_fi_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static int tcpx_pep_listen(struct fid_pep *pep)
{
	struct tcpx_pep *tcpx_pep;
	struct tcpx_fabric *tcpx_fabric;

	tcpx_pep = container_of(pep,struct tcpx_pep, util_pep.pep_fid);
	tcpx_fabric = container_of(tcpx_pep->util_pep.fabric,
				   struct tcpx_fabric, util_fabric);

	if (listen(tcpx_pep->sock, SOMAXCONN)) {
		FI_WARN(&tcpx_prov, FI_LOG_EP_CTRL,
			"socket listen failed\n");
		return -errno;
	}

	fastlock_acquire(&tcpx_fabric->poll_mgr.lock);
	dlist_insert_tail(&tcpx_pep->poll_info.entry, &tcpx_fabric->poll_mgr.list);
	fastlock_release(&tcpx_fabric->poll_mgr.lock);
	fd_signal_set(&tcpx_fabric->poll_mgr.signal);

	return 0;

}

static struct fi_ops_cm tcpx_pep_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.setname = fi_no_setname,
	.getname = fi_no_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = tcpx_pep_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
	.shutdown = fi_no_shutdown,
	.join = fi_no_join,
};


static int tcpx_verify_info(uint32_t version, struct fi_info *info)
{
	/* TODO: write me! */
	return 0;
}

static struct fi_ops_ep tcpx_pep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.getopt = fi_no_getopt,
	.setopt = fi_no_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};


int tcpx_passive_ep(struct fid_fabric *fabric, struct fi_info *info,
		    struct fid_pep **pep, void *context)
{
	struct tcpx_pep *_pep;
	struct addrinfo hints, *result, *iter;
	char sa_ip[INET_ADDRSTRLEN] = {0};
	char sa_port[NI_MAXSERV] = {0};
	int ret;

	if (!info) {
		FI_WARN(&tcpx_prov, FI_LOG_EP_CTRL,"invalid info\n");
		return -FI_EINVAL;

	}

	ret = tcpx_verify_info(fabric->api_version, info);
	if (ret)
		return ret;

	_pep = calloc(1, sizeof(*_pep));
	if (!_pep)
		return -FI_ENOMEM;

	ret = ofi_pep_init(fabric, info, &_pep->util_pep, context);
	if (ret)
		goto err1;

	_pep->info = *info;
	_pep->poll_info.fid = &_pep->util_pep.pep_fid.fid;
	_pep->poll_info.type = PASSIVE_SOCK;
	_pep->poll_info.flags = 0;
	_pep->poll_info.cm_data_sz = 0;
	dlist_init(&_pep->poll_info.entry);
	_pep->sock = INVALID_SOCKET;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if (info->src_addr) {
		switch (info->addr_format) {
		case FI_SOCKADDR:
		case FI_SOCKADDR_IN:
		case FI_SOCKADDR_IN6:
			ret = getnameinfo(info->src_addr, info->src_addrlen,
					  sa_ip, INET_ADDRSTRLEN,
					  sa_port, NI_MAXSERV, 0);
			if (ret) {
				FI_WARN(&tcpx_prov, FI_LOG_EP_CTRL,
					"pep initialization failed\n");
				goto err2;
			}
			break;
		default:
			FI_WARN(&tcpx_prov, FI_LOG_EP_CTRL,
				"invalid source address format\n");
			ret = -FI_EINVAL;
			goto err2;
		}
		ret = getaddrinfo(sa_ip, sa_port, &hints, &result);
	} else {
		ret = getaddrinfo("localhost", NULL, &hints, &result);
	}

	if (ret) {
		ret = -FI_EINVAL;
		FI_WARN(&tcpx_prov, FI_LOG_EP_CTRL,"getaddrinfo failed");
		goto err2;
	}

	for (iter = result; iter; iter = iter->ai_next) {
		_pep->sock = ofi_socket(iter->ai_family, iter->ai_socktype,
					iter->ai_protocol);
		if (_pep->sock == INVALID_SOCKET)
			continue;

		ret = tcpx_setup_socket(_pep->sock);
		if (ret) {
			ofi_close_socket(_pep->sock);
			_pep->sock = INVALID_SOCKET;
			continue;
		}

		if (bind(_pep->sock, result->ai_addr, result->ai_addrlen)) {
			FI_WARN(&tcpx_prov, FI_LOG_EP_CTRL,
				"failed to bind listener: %s\n", strerror(errno));
			ofi_close_socket(_pep->sock);
			_pep->sock = INVALID_SOCKET;
		} else {
			break;
		}
	}
	freeaddrinfo(result);

	if (_pep->sock == INVALID_SOCKET) {
		FI_WARN(&tcpx_prov, FI_LOG_EP_CTRL,
			"failed to create listener: %s\n", strerror(errno));
		ret = -FI_EIO;
		goto err2;
	}

	_pep->util_pep.pep_fid.fid.ops = &tcpx_pep_fi_ops;
	_pep->util_pep.pep_fid.cm = &tcpx_pep_cm_ops;
	_pep->util_pep.pep_fid.ops = &tcpx_pep_ops;

	*pep = &_pep->util_pep.pep_fid;
	return 0;
err2:
	ofi_pep_close(&_pep->util_pep);
err1:
	free(_pep);
	return ret;
}
