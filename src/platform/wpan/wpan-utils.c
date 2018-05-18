/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "wpan-utils.h"

#include "platform/nl802154.h"
#include "platform/nm-netlink.h"

#define _NMLOG_PREFIX_NAME "wpan-nl802154"
#define _NMLOG(level, domain, ...) \
	G_STMT_START { \
		nm_log ((level), (domain), NULL, NULL, \
		        "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
		        _NMLOG_PREFIX_NAME \
		        _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
	} G_STMT_END

/*****************************************************************************/

struct WpanData {
	int ifindex;
	guint refcount;
	struct nl_sock *nl_sock;
	int id;
};

WpanData *
wpan_utils_init (int ifindex, struct nl_sock *genl, gboolean check_scan)
{
	WpanData *data;
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	int id;

	g_return_val_if_fail (ifindex > 0, NULL);

	if (!genl)
		return NULL;

	id = genl_ctrl_resolve (genl, "nl802154");
	if (id < 0) {
		_LOGD (LOGD_PLATFORM, "genl_ctrl_resolve: failed to resolve \"nl802154\"");
		return NULL;
	}

	data = g_slice_new0 (WpanData);
	data->ifindex = ifindex;
	data->refcount = 1;
	data->nl_sock = genl;
	data->id = id;

	return data;
}


void
wpan_utils_ref (WpanData *data)
{
	g_return_if_fail (data != NULL);
	g_return_if_fail (data->refcount > 0);

	data->refcount++;
}

void
wpan_utils_unref (WpanData *data)
{
	g_return_if_fail (data != NULL);
	g_return_if_fail (data->refcount > 0);

	data->refcount--;
	if (data->refcount == 0)
		g_slice_free (WpanData, data);
}

/*****************************************************************************/

static int
ack_handler (struct nl_msg *msg, void *arg)
{
	int *done = arg;
	*done = 1;
	return NL_STOP;
}

static int
finish_handler (struct nl_msg *msg, void *arg)
{
	int *done = arg;
	*done = 1;
	return NL_SKIP;
}

static int
error_handler (struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	int *done = arg;
	*done = err->error;
	return NL_SKIP;
}

static struct nl_msg *
_nl802154_alloc_msg (int id, int ifindex, guint32 cmd, guint32 flags)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;

	msg = nlmsg_alloc ();
	genlmsg_put (msg, 0, 0, id, 0, flags, cmd, 0);
	NLA_PUT_U32 (msg, NL802154_ATTR_IFINDEX, ifindex);
	return g_steal_pointer (&msg);

nla_put_failure:
	return NULL;
}

static struct nl_msg *
nl802154_alloc_msg (WpanData *data, guint32 cmd, guint32 flags)
{
	return _nl802154_alloc_msg (data->id, data->ifindex, cmd, flags);
}

static int
_nl802154_send_and_recv (struct nl_sock *nl_sock,
                         struct nl_msg *msg,
                         int (*valid_handler) (struct nl_msg *, void *),
                         void *valid_data)
{
	int err;
	int done = 0;
	const struct nl_cb cb = {
		.err_cb     = error_handler,
		.err_arg    = &done,
		.finish_cb  = finish_handler,
		.finish_arg = &done,
		.ack_cb     = ack_handler,
		.ack_arg    = &done,
		.valid_cb   = valid_handler,
		.valid_arg  = valid_data,
	};

	g_return_val_if_fail (msg != NULL, -ENOMEM);

	err = nl_send_auto (nl_sock, msg);
	if (err < 0)
		return err;

	/* Loop until one of our NL callbacks says we're done; on success
	 * done will be 1, on error it will be < 0.
	 */
	while (!done) {
		err = nl_recvmsgs (nl_sock, &cb);
		if (err < 0 && err != -EAGAIN) {
			_LOGW (LOGD_PLATFORM, "nl_recvmsgs() error: (%d) %s",
			       err, nl_geterror (err));
			break;
		}
	}

	if (err >= 0 && done < 0)
		err = done;
	return err;
}

static int
nl802154_send_and_recv (WpanData *data,
                        struct nl_msg *msg,
                        int (*valid_handler) (struct nl_msg *, void *),
                        void *valid_data)
{
	return _nl802154_send_and_recv (data->nl_sock, msg,
	                                valid_handler, valid_data);
}

struct nl802154_interface {
	guint16 pan_id;
	guint16 short_addr;

	gboolean valid;
};

static int
nl802154_get_interface_handler (struct nl_msg *msg, void *arg)
{
	struct nl802154_interface *info = arg;
	struct genlmsghdr *gnlh = nlmsg_data (nlmsg_hdr (msg));
	struct nlattr *tb[NL802154_ATTR_MAX + 1] = { 0, };
	static const struct nla_policy nl802154_policy[NL802154_ATTR_MAX + 1] = {
		[NL802154_ATTR_PAN_ID] =            { .type = NLA_U16 },
		[NL802154_ATTR_SHORT_ADDR] =        { .type = NLA_U16 },
	};

	if (nla_parse (tb, NL802154_ATTR_MAX, genlmsg_attrdata (gnlh, 0),
	               genlmsg_attrlen (gnlh, 0), nl802154_policy) < 0)
	return NL_SKIP;

	if (tb[NL802154_ATTR_PAN_ID])
		info->pan_id = le16toh (nla_get_u16 (tb[NL802154_ATTR_PAN_ID]));

	if (tb[NL802154_ATTR_SHORT_ADDR])
		info->short_addr = le16toh (nla_get_u16 (tb[NL802154_ATTR_SHORT_ADDR]));

	info->valid = TRUE;

	return NL_SKIP;
}

static void
nl802154_get_interface (WpanData *data,
                        struct nl802154_interface *interface)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;

	memset (interface, 0, sizeof (*interface));

	msg = nl802154_alloc_msg (data, NL802154_CMD_GET_INTERFACE, 0);

	nl802154_send_and_recv (data, msg, nl802154_get_interface_handler, interface);
}

/*****************************************************************************/

guint16
wpan_utils_get_pan_id (WpanData *data)
{
	struct nl802154_interface interface;

	nl802154_get_interface (data, &interface);

	return interface.pan_id;
}

gboolean
wpan_utils_set_pan_id (WpanData *data, const guint16 pan_id)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	int err;

	g_return_val_if_fail (data != NULL, FALSE);

	msg = nl802154_alloc_msg (data, NL802154_CMD_SET_PAN_ID, 0);
	NLA_PUT_U16 (msg, NL802154_ATTR_PAN_ID, htole16 (pan_id));
	err = nl802154_send_and_recv (data, msg, NULL, NULL);
	return err >= 0;

nla_put_failure:
	return FALSE;
}

guint16
wpan_utils_get_short_addr (WpanData *data)
{
	struct nl802154_interface interface;

	nl802154_get_interface (data, &interface);

	return interface.short_addr;
}

gboolean
wpan_utils_set_short_addr (WpanData *data, const guint16 short_addr)
{
	nm_auto_nlmsg struct nl_msg *msg = NULL;
	int err;

	g_return_val_if_fail (data != NULL, FALSE);

	msg = nl802154_alloc_msg (data, NL802154_CMD_SET_SHORT_ADDR, 0);
	NLA_PUT_U16 (msg, NL802154_ATTR_SHORT_ADDR, htole16 (short_addr));
	err = nl802154_send_and_recv (data, msg, NULL, NULL);
	return err >= 0;

nla_put_failure:
	return FALSE;
}
