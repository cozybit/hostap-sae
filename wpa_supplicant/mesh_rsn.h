/*
 * wpa_supplicant - mesh
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

#ifndef MESH_RSN_H
#define MESH_RSN_H

int mesh_rsn_init(struct wpa_global *global, struct wpa_supplicant *wpa_s);
void mesh_rsn_deinit(struct wpa_supplicant *wpa_s);

/* starts or joins a mesh network */
/* JC: needed?  or this should be done on mesh_rsn_init */
int mesh_join(struct wpa_supplicant *wpa_s);

/* kernel notifies a new candidate in range */
/* JC: mesh_rsn massages and passes that info to SAE */
int mesh_rsn_start(struct wpa_supplicant *wpa_s, u8 *peer_mac);

/* xmit a management frame */
int mesh_tx_mgmt_frame(struct wpa_supplicant *wpa_s);

/* rx an auth management frame from wpa_supplicant */
int mesh_rsn_rx_frame(struct wpa_supplicant *wpa_s,
		const struct ieee80211_mgmt *frame, int frame_len);

/* create an unauthenticated peer candidate */
/* JC: in response to NEW_CANDIDATE events as well as completed
 * authentications (fin()) */
int mesh_new_unauth_candidate(struct wpa_supplicant *wpa_s);

/* authenticate a peer candidate */
/* JC: in response to fin() events */
int mesh_new_unauth_candidate(struct wpa_supplicant *wpa_s);

#endif /* MESH_RSN_H */
