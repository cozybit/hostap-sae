/*
 * wpa_supplicant - mesh RSN
 * Copyright (c) 2011, cozybit Inc.
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
#include "eloop.h"
#include "common/ieee802_11_common.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_ctrl.h"
#include "rsn_supp/wpa_ie.h"
#include "rsn_supp/wpa.h"
#include "rsn_supp/wpa_i.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "ap.h"
#include "config_ssid.h"
#include "config.h"
#include "mlme.h"
#include "notify.h"
#include "scan.h"
#include "bss.h"
#include "sae/sae.h"
#include "sae/service.h"

service_context srvctx;

static struct wpa_ssid * find_valid_mesh_ssid_in_group(
		struct wpa_supplicant *wpa_s,
		struct wpa_ssid *group)
{
	struct wpa_ssid *ssid;

	for (ssid = group; ssid; ssid = ssid->pnext) {
		if (ssid->disabled) {
			wpa_dbg(wpa_s, MSG_DEBUG, "   skip - disabled");
			continue;
		}

		if (ssid->mode != WPAS_MODE_MESH) {
			wpa_dbg(wpa_s, MSG_DEBUG, "   skip - non-mesh");
			continue;
		}

		/* Beyond this point, we can assume the user wanted mesh so
		 * make the messages warnings */
		if (!ssid->ssid) {
			wpa_dbg(wpa_s, MSG_WARNING, "   skip - missing meshid");
			continue;
		}

		/* TODO: Should support WPA_KEY_MGMT_NONE */
		if (!(ssid->key_mgmt & WPA_KEY_MGMT_SAE)) {
			wpa_dbg(wpa_s, MSG_WARNING, "   skip - non-SAE key "
				"not allowed");
			continue;
		}

		if (!(ssid->group_cipher & WPA_CIPHER_CCMP)) {
			wpa_dbg(wpa_s, MSG_WARNING, "   skip - cipher not "
				"not supported");
		}

		if (!(ssid->pairwise_cipher & WPA_CIPHER_CCMP)) {
			wpa_dbg(wpa_s, MSG_WARNING, "   skip - cipher not "
				"not supported");
		}

		if (!ssid->frequency) {
			wpa_dbg(wpa_s, MSG_WARNING, "   skip - freq required");
			continue;
		}

		if (!ssid->sae_groups ||
				(ssid->sae_groups && !ssid->sae_groups[0])) {
			wpa_dbg(wpa_s, MSG_WARNING, "   skip - sae group "
					"list required");
			continue;
		}

		/* Valid mesh configuration found */
		return ssid;
	}

	/* No matching configuration found */
	return NULL;
}

struct wpa_ssid * find_mesh_ssid_in_config(struct wpa_supplicant *wpa_s)
{
	struct wpa_ssid *selected = NULL;
	int prio;

	wpa_printf(MSG_DEBUG, "Mesh: Looking for a mesh network config entry");
	for (prio = 0; prio < wpa_s->conf->num_prio; prio++) {
		selected = find_valid_mesh_ssid_in_group(wpa_s,
				wpa_s->conf->pssid[prio]);
		if (selected)
			break;
	}

	return selected;
}

/**
 * mesh_rsn_init - Initialize mesh RSN module for %wpa_supplicant
 * @global: Pointer to global data from wpa_supplicant_init()
 * @wpa_s: Pointer to wpa_supplicant data from wpa_supplicant_add_iface()
 * Returns: 0 on success, -1 on failure
 */
int mesh_rsn_init(struct wpa_global *global, struct wpa_supplicant *wpa_s)
{
	struct sae_config saeconf;
	struct wpa_bss *bss;
	struct wpa_ssid *ssid;
	struct wpa_sm sm;
	u8 rsn_ie[22];
	int i;

	/* See if there is a valid mesh network entry in the conf file */
	ssid = find_mesh_ssid_in_config(wpa_s);
	if (ssid == NULL) {
		/* User did not want mesh. Just move on */
		wpa_printf(MSG_DEBUG, "Mesh: no valid mesh configuration found");
		return 0;
	}

	/* User wants mesh, check that the chosen driver is mesh capable */
	if (!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_MESH_CAPABLE))
		return -1;

	/* Allocate service context for SAE */
	srvctx = srv_create_context();
	if (srvctx == NULL)
		wpa_printf(MSG_ERROR, "Mesh: SAE context allocation failed");


	/* wpa_supplicant_associate() takes two parameters: an ssid structure
	 * populated from the configuration file, and a bss struct populated
	 * from scan results.  For mesh, this separation does not apply: we
	 * always want to join the mesh if the config file tells us to do so.
	 *
	 * Below we just craft a bss structure that will do the job.
	 */
	bss = os_malloc(sizeof(struct wpa_bss) + sizeof(rsn_ie));

	memset(bss, 0, sizeof(*bss));
	bss->freq = ssid->frequency;

	/* In mesh mode, we reuse the ssid field to be mesh id */
	os_memcpy((char *)bss->ssid, ssid->ssid, ssid->ssid_len);
	bss->ssid_len = strlen((const char*)bss->ssid);

	/* Construct the RSN IE */
	os_memset(&sm, 0, sizeof(sm));
	sm.proto = ssid->proto;
	sm.pairwise_cipher = ssid->pairwise_cipher;
	sm.group_cipher = ssid->group_cipher;
	sm.key_mgmt = ssid->key_mgmt;
	if ((bss->ie_len = wpa_gen_wpa_ie(&sm, rsn_ie, sizeof(rsn_ie))) < 0)
		wpa_printf(MSG_ERROR, "Can't generate Mesh RSN IE");

	/* stick it at the end of bss (see struct wpa_bss) */
	os_memcpy(bss + 1, rsn_ie, sizeof(rsn_ie));

	/* Done crafting the bss struct. Now initialize the SAE library */
	os_memcpy(&saeconf, ssid->ssid, sizeof(saeconf));
	for (i = 0; i < SAE_MAX_EC_GROUPS; i++) {
		if (!ssid->sae_groups[i])
			break;
		saeconf.group[i] = ssid->sae_groups[i];
	}

	saeconf.num_groups = i;
	saeconf.debug = ssid->sae_debug;
	saeconf.blacklist_timeout = ssid->sae_blacklist;
	saeconf.retrans = ssid->sae_retrans;
	saeconf.open_threshold = ssid->sae_thresh;
	saeconf.pmk_expiry = ssid->sae_lifetime;
	saeconf.giveup_threshold = ssid->sae_giveup;

	if (SAE_MAX_PASSWORD_LEN > strlen(ssid->passphrase) + 1)
		os_memcpy(saeconf.pwd, ssid->passphrase, strlen(ssid->passphrase) + 1);
	else {
		wpa_printf(MSG_ERROR, "Mesh: Can't copy passphrase to libSAE");
		return -1;
	}

	if (sae_initialize("UNUSED", &saeconf) < 0)
		wpa_printf(MSG_ERROR, "Mesh: SAE initialization failed");

	wpa_supplicant_associate(wpa_s, bss, ssid);

	os_free(bss);

	wpa_printf(MSG_DEBUG, "Mesh: Intialization completed");
	return 0;
}


/**
 * mesh_rsn_deinit - Deinitialize per-interface P2P data
 * @wpa_s: Pointer to wpa_supplicant data from wpa_supplicant_add_iface()
 *
 * This function deinitialize per-interface mesh data.
 */
void mesh_rsn_deinit(struct wpa_supplicant *wpa_s)
{
	/* TODO: tell libsae to cancel timouts and other state cleanup */
}

int mesh_rsn_start(struct wpa_supplicant *wpa_s, u8 *peer_mac)
{
	struct ieee80211_mgmt_frame bcn;

	/* TODO: Do we know at this point that the RSN IE has been parsed and
	 * that it is compatible with our mesh security? Methinks not. */

	/* libsae only understands the language of frames:  craft a fake beacon to
	 * trigger an authentication */
	os_memset(&bcn, 0, sizeof(bcn));
	bcn.frame_control = htole16(
			(IEEE802_11_FC_TYPE_MGMT << 2 |
			 IEEE802_11_FC_STYPE_BEACON << 4));

	os_memcpy(bcn.sa, peer_mac, ETH_ALEN);

	if (process_mgmt_frame(&bcn, sizeof(bcn), wpa_s->own_addr, wpa_s))
		wpa_printf(MSG_ERROR, "libsae: process_mgmt_frame failed");
	return 0;
}

int mesh_rsn_rx_frame(struct wpa_supplicant *wpa_s,
		const struct ieee80211_mgmt *frame, int frame_len)
{
	if (!frame)
		return -EINVAL;
	if (process_mgmt_frame((struct ieee80211_mgmt_frame *) frame, frame_len,
				wpa_s->own_addr, wpa_s))
		wpa_printf(MSG_ERROR, "libsae: process_mgmt_frame failed");
	return 0;
}

void fin(int status, char *peer, char *buf, int len, void *cookie)
{
	struct hostapd_sta_add_params params;
	struct wpa_supplicant *wpa_s = cookie;
	/* TODO: get these rates from somewhere.  Probably from NL80211
	 * NEW_PEER_CANDIDATE event. */
	uint8_t supported_rates[] = { 2, 4, 10, 22, 96, 108 };

	wpa_printf(MSG_DEBUG, "libsae: candidate peer (" MACSTR ") status %d", MAC2STR(peer), status);
	wpa_hexdump(MSG_DEBUG, "SAE pmk", (u8 *) buf, len);
	if (status != WLAN_STATUS_SUCCESSFUL)
		return;

	if (!wpa_s) {
		wpa_printf(MSG_ERROR, "libsae lost our context. Can't create new station!");
		return;
	}

	/* Create a new station */
	memset(&params, 0, sizeof(params));
	params.aid = 1;
	params.listen_interval = 100;
	params.supp_rates_len = sizeof(supported_rates);
	params.supp_rates = supported_rates;
	params.addr = (u8 *)peer;
	params.ht_capabilities = NULL;
	wpa_drv_sta_add(wpa_s, &params);
	wpa_supplicant_cancel_auth_timeout(wpa_s);
}

int meshd_write_mgmt(char *buf, int len, void *cookie)
{
	if (!cookie) {
		wpa_printf(MSG_ERROR, "libsae lost our context. Can't send frame!");
		return 0;
	}
	if (wpa_drv_send_mlme((struct wpa_supplicant *) cookie,(u8*) buf, len) < 0)
		wpa_printf(MSG_ERROR, "wpa_drv_send_mlme failed\n");

	return len;
}
