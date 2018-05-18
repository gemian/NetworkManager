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

#ifndef __WPAN_UTILS_H__
#define __WPAN_UTILS_H__

#include <net/ethernet.h>

#include "nm-dbus-interface.h"
#include "platform/nm-netlink.h"

typedef struct WpanData WpanData;

WpanData *wpan_utils_init (int ifindex, struct nl_sock *genl, gboolean check_scan);

void wpan_utils_ref (WpanData *data);
void wpan_utils_unref (WpanData *data);

guint16 wpan_utils_get_pan_id (WpanData *data);
gboolean wpan_utils_set_pan_id (WpanData *data, const guint16 pan_id);

guint16 wpan_utils_get_short_addr (WpanData *data);
gboolean wpan_utils_set_short_addr (WpanData *data, const guint16 short_addr);

#endif  /* __WPAN_UTILS_H__ */
