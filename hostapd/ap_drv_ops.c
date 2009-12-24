/*
 * hostapd - Driver operations
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "includes.h"

#include "common.h"
#include "hostapd.h"
#include "sta_info.h"
#include "driver_i.h"


static int hostapd_sta_flags_to_drv(int flags)
{
	int res = 0;
	if (flags & WLAN_STA_AUTHORIZED)
		res |= WPA_STA_AUTHORIZED;
	if (flags & WLAN_STA_WMM)
		res |= WPA_STA_WMM;
	if (flags & WLAN_STA_SHORT_PREAMBLE)
		res |= WPA_STA_SHORT_PREAMBLE;
	if (flags & WLAN_STA_MFP)
		res |= WPA_STA_MFP;
	return res;
}


static int hostapd_set_ap_wps_ie(struct hostapd_data *hapd,
				 const struct wpabuf *beacon,
				 const struct wpabuf *proberesp)
{
	if (hapd->driver == NULL || hapd->driver->set_ap_wps_ie == NULL)
		return 0;
	return hapd->driver->set_ap_wps_ie(hapd->conf->iface, hapd->drv_priv,
					   beacon, proberesp);
}


static int hostapd_send_mgmt_frame(struct hostapd_data *hapd, const void *msg,
			   size_t len)
{
	if (hapd->driver == NULL || hapd->driver->send_mlme == NULL)
		return 0;
	return hapd->driver->send_mlme(hapd->drv_priv, msg, len);
}


static int hostapd_send_eapol(struct hostapd_data *hapd, const u8 *addr,
			      const u8 *data, size_t data_len, int encrypt)
{
	if (hapd->driver == NULL || hapd->driver->hapd_send_eapol == NULL)
		return 0;
	return hapd->driver->hapd_send_eapol(hapd->drv_priv, addr, data,
					     data_len, encrypt,
					     hapd->own_addr);
}


static int hostapd_set_authorized(struct hostapd_data *hapd,
				  struct sta_info *sta, int authorized)
{
	if (authorized) {
		return hostapd_sta_set_flags(hapd, sta->addr,
					     hostapd_sta_flags_to_drv(
						     sta->flags),
					     WPA_STA_AUTHORIZED, ~0);
	}

	return hostapd_sta_set_flags(hapd, sta->addr,
				     hostapd_sta_flags_to_drv(sta->flags),
				     0, ~WPA_STA_AUTHORIZED);
}


static int hostapd_set_key(const char *ifname, struct hostapd_data *hapd,
			   wpa_alg alg, const u8 *addr, int key_idx,
			   int set_tx, const u8 *seq, size_t seq_len,
			   const u8 *key, size_t key_len)
{
	if (hapd->driver == NULL || hapd->driver->set_key == NULL)
		return 0;
	return hapd->driver->set_key(ifname, hapd->drv_priv, alg, addr,
				     key_idx, set_tx, seq, seq_len, key,
				     key_len);
}


static int hostapd_read_sta_data(struct hostapd_data *hapd,
				 struct hostap_sta_driver_data *data,
				 const u8 *addr)
{
	if (hapd->driver == NULL || hapd->driver->read_sta_data == NULL)
		return -1;
	return hapd->driver->read_sta_data(hapd->drv_priv, data, addr);
}


static int hostapd_sta_clear_stats(struct hostapd_data *hapd, const u8 *addr)
{
	if (hapd->driver == NULL || hapd->driver->sta_clear_stats == NULL)
		return 0;
	return hapd->driver->sta_clear_stats(hapd->drv_priv, addr);
}


static int hostapd_set_sta_flags(struct hostapd_data *hapd,
				 struct sta_info *sta)
{
	int set_flags, total_flags, flags_and, flags_or;
	total_flags = hostapd_sta_flags_to_drv(sta->flags);
	set_flags = WPA_STA_SHORT_PREAMBLE | WPA_STA_WMM | WPA_STA_MFP;
	if (!hapd->conf->ieee802_1x && !hapd->conf->wpa &&
	    sta->flags & WLAN_STA_AUTHORIZED)
		set_flags |= WPA_STA_AUTHORIZED;
	flags_or = total_flags & set_flags;
	flags_and = total_flags | ~set_flags;
	return hostapd_sta_set_flags(hapd, sta->addr, total_flags,
				     flags_or, flags_and);
}


static int hostapd_set_drv_ieee8021x(struct hostapd_data *hapd,
				     const char *ifname, int enabled)
{
	struct wpa_bss_params params;
	os_memset(&params, 0, sizeof(params));
	params.ifname = ifname;
	params.enabled = enabled;
	if (enabled) {
		params.wpa = hapd->conf->wpa;
		params.ieee802_1x = hapd->conf->ieee802_1x;
		params.wpa_group = hapd->conf->wpa_group;
		params.wpa_pairwise = hapd->conf->wpa_pairwise;
		params.wpa_key_mgmt = hapd->conf->wpa_key_mgmt;
		params.rsn_preauth = hapd->conf->rsn_preauth;
	}
	return hostapd_set_ieee8021x(hapd, &params);
}


void hostapd_set_driver_ops(struct hostapd_driver_ops *ops)
{
	ops->set_ap_wps_ie = hostapd_set_ap_wps_ie;
	ops->send_mgmt_frame = hostapd_send_mgmt_frame;
	ops->send_eapol = hostapd_send_eapol;
	ops->set_authorized = hostapd_set_authorized;
	ops->set_key = hostapd_set_key;
	ops->read_sta_data = hostapd_read_sta_data;
	ops->sta_clear_stats = hostapd_sta_clear_stats;
	ops->set_sta_flags = hostapd_set_sta_flags;
	ops->set_drv_ieee8021x = hostapd_set_drv_ieee8021x;
}