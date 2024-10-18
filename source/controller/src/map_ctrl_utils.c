/*
 * Copyright (c) 2019-2022 AirTies Wireless Networks
 *
 * Licensed under the BSD+Patent License.
*/

/************* COPYRIGHT AND CONFIDENTIALITY INFORMATION NOTICE *************
** Copyright (c) [2019] – [Technicolor Delivery Technologies, SAS]          *
** All Rights Reserved                                                      *
** The source code form of this Open Source Project components              *
** is subject to the terms of the BSD-2-Clause-Patent.                      *
** You can redistribute it and/or modify it under the terms of              *
** the BSD-2-Clause-Patent. (https://opensource.org/licenses/BSDplusPatent) *
** See COPYING file/LICENSE file for more details.                          *
****************************************************************************/

/*#######################################################################
#                       INCLUDES                                        #
########################################################################*/
#define LOG_TAG "utils"

#include "map_ctrl_utils.h"
#include "map_ctrl_cmdu_tx.h"
#include "map_ctrl_topology_tree.h"

#include "map_info.h"
#include "map_80211.h"
#include "arraylist.h"
#include "map_topology_tree.h"

/*#######################################################################
#                       DEFINES                                         #
########################################################################*/
#define min(a,b) ((a) < (b) ? (a) : (b))

/*#######################################################################
#                       PRIVATE FUNCTIONS                               #
########################################################################*/
/* Find op_class that matches op_class_nr/channel
   Note: channel is center channel for 80/160/320MHz
*/
static map_op_class_t *find_op_class(map_op_class_list_t *list, uint8_t op_class_nr, uint8_t channel, bool in_channel_list)
{
    uint8_t i;

    for (i = 0; i < list->op_classes_nr; i++) {
        map_op_class_t *op_class = &list->op_classes[i];

        /* Channel matches when channel list is empty or it is in the channel list */
        if (op_class->op_class == op_class_nr &&
            map_is_channel_in_op_class(op_class->op_class, channel) &&
            (map_cs_nr(&op_class->channels) == 0 ||
             ((in_channel_list && map_cs_is_set(&op_class->channels, channel)) ||
              (!in_channel_list && !map_cs_is_set(&op_class->channels, channel))))) {
            return op_class;
        }
    }

    return NULL; /* Not found */
}

/* Get preference of op_class_nr/channel */
static uint8_t get_channel_pref(map_op_class_list_t *list, uint8_t op_class_nr, uint8_t channel)
{
    /* Empty channel list or channel must be in channel list */
    map_op_class_t *op_class = find_op_class(list, op_class_nr, channel, true);

    return op_class ? op_class->pref : MAP_PREF_SCORE_15;
}

/* Check if op_class_nr/channel is supported in op_class */
static bool is_channel_operable(map_op_class_list_t *cap_list, uint8_t op_class_nr, uint8_t channel)
{
    /* Empty channel list or channel must be NOT in channel list */
    return find_op_class(cap_list, op_class_nr, channel, false);
}

/* Check if op_class_nr/channel is disallowed */
static bool is_channel_disallowed(map_op_class_list_t *disallow_list, uint8_t op_class_nr, uint8_t channel)
{
    uint8_t i;

    for (i = 0; i < disallow_list->op_classes_nr; i++) {
        map_op_class_t *op_class = &disallow_list->op_classes[i];

        if (!op_class->enable) {
            continue; 
        }

        /* Channel matches when channel list is empty or it is in the channel list */
        if (op_class->op_class == op_class_nr && map_is_channel_in_op_class(op_class->op_class, channel)) {
            return map_cs_is_set(&op_class->channels, channel);
        }
    }

    return false;
}

/* Add op_class with pref and channel to list (if not present yet)
   Note: list is guaranteed to be big enough
*/
static void check_add_op_class_channel(map_op_class_list_t *merged_list, map_op_class_list_t *cap_list,
                                       map_op_class_list_t *other_list, map_op_class_list_t *disallowed_list,
                                       map_op_class_t *op_class, uint8_t channel)
{
    map_op_class_t *find_op_class = NULL; /* eliminate warning */
    uint8_t         pref, other_pref;
    uint8_t         i;

    /* Do not add static non operable channels */
    if (!is_channel_operable(cap_list, op_class->op_class, channel)) {
        return;
    }

    if (is_channel_disallowed(disallowed_list, op_class->op_class, channel)) {
        return;
    }

    /* Get pref in other list, and use minimum */
    other_pref = get_channel_pref(other_list, op_class->op_class, channel);
    pref = min(op_class->pref, other_pref);

    /* Do not add max pref */
    if (pref == MAP_PREF_SCORE_15) {
        return;
    }

    /* Find op_class/pref... */
    for (i = 0; i < merged_list->op_classes_nr; i++) {
        find_op_class = &merged_list->op_classes[i];

        if (find_op_class->op_class == op_class->op_class && find_op_class->pref == pref) {
            break;
        }
    }

    /* ...op_class/pref not found */
    if (i == merged_list->op_classes_nr) {
        find_op_class = &merged_list->op_classes[merged_list->op_classes_nr++];
        find_op_class->op_class = op_class->op_class;
        find_op_class->pref     = pref;
        find_op_class->reason   = 0; /* TODO... */
    }

    /* Add channel */
    map_cs_set(&find_op_class->channels, channel);
}

/* Add all op_classes/channels from add_list to merged_list, using lowest pref from add_list or other_list */
static void merge_pref_op_class_list_add(map_op_class_list_t *merged_list, map_op_class_list_t *cap_list,
                                         map_op_class_list_t *add_list, map_op_class_list_t *other_list,
                                         map_op_class_list_t *disallowed_list)
{
    map_channel_set_t ch_set;
    uint8_t           channel, i;
    bool              is_center_channel;

    for (i = 0; i < add_list->op_classes_nr; i++) {
        map_op_class_t *op_class = &add_list->op_classes[i];

        /* Add all channels when channel_count is 0 */
        if (map_cs_nr(&op_class->channels) == 0) {
            if (0 != map_get_is_center_channel_from_op_class(op_class->op_class, &is_center_channel)) {
                continue;
            }

            if ((is_center_channel && map_get_center_channel_set_from_op_class(op_class->op_class, &ch_set)) ||
                (!is_center_channel && map_get_channel_set_from_op_class(op_class->op_class, &ch_set))) {
                continue;
            }

            map_cs_foreach(&ch_set, channel) {
                check_add_op_class_channel(merged_list, cap_list, other_list, disallowed_list, op_class, channel);
            }
        } else {
            map_cs_foreach(&op_class->channels, channel) {
                check_add_op_class_channel(merged_list, cap_list, other_list, disallowed_list, op_class, channel);
            }
        }
    }
}

/* Add all op_classes/channels from disallowed_list to merged_list */
static void merge_disallowed_op_class_list_add(map_op_class_list_t *merged_list, map_op_class_list_t *cap_list,
                                               map_op_class_list_t *disallowed_list)
{
    uint8_t i;

    for (i = 0; i < disallowed_list->op_classes_nr; i++) {
        map_op_class_t *op_class = &disallowed_list->op_classes[i];
        uint8_t channel, j;

        if (op_class->enable == false) {
            continue;
        }

        if (map_cs_nr(&op_class->channels) == 0) {
            continue;
        }

        map_cs_foreach(&op_class->channels, channel) {
            map_op_class_t *find_op_class = NULL;

            /* Do not add static non operable channels */
            if (!is_channel_operable(cap_list, op_class->op_class, channel)) {
                continue;
            }

            /* Find op_class/pref... */
            for (j = 0; j < merged_list->op_classes_nr; j++) {
                find_op_class = &merged_list->op_classes[j];

                if (find_op_class->op_class == op_class->op_class && find_op_class->pref == 0) {
                    break;
                }
            }

            /* ...op_class/pref not found */
            if (j == merged_list->op_classes_nr) {
                find_op_class = &merged_list->op_classes[merged_list->op_classes_nr++];
                find_op_class->op_class = op_class->op_class;
                find_op_class->pref     = 0;
                find_op_class->reason   = 0; /* TODO... */
            }

            /* Add channel */
            map_cs_set(&find_op_class->channels, channel);
        }
    }

}

static int comp_op_class(const void *obj1, const void *obj2)
{
    const map_op_class_t *a = obj1;
    const map_op_class_t *b = obj2;

    /* op_class: low->high, pref: low->high */
    return (a->op_class == b->op_class) ? a->pref - b->pref : a->op_class - b->op_class;
}

static void map_update_radio_ctl_channels(map_radio_info_t *radio)
{
    map_chan_sel_cfg_t  *cfg               = &get_controller_cfg()->chan_sel;
    bandlock_5g_t        bandlock_5g       = cfg->bandlock_5g;
    bool                 is_5g_low_high    = map_is_5g_low_high(radio);
    map_op_class_list_t *cap_op_class_list = &radio->cap_op_class_list;
    int                  i;

    /* Note:
        - cap_ctl_channels: all ctl channels from cap op_class list
        - ctl_channels    : all ctl channels from op_class list that are allowed after applying config
                            (bandlock and allowed channel list)
    */

    map_cs_unset_all(&radio->cap_ctl_channels);
    map_cs_unset_all(&radio->ctl_channels);

    /* Fill supported channel set based on 20MHz operating classes */
    for (i = 0; i < cap_op_class_list->op_classes_nr; i++) {
        map_op_class_t    *cap_op_class = &cap_op_class_list->op_classes[i];
        uint8_t            op_class = cap_op_class->op_class;
        map_channel_set_t  ch_set;
        uint16_t           bw;
        uint8_t            band, channel;
        bool               bandlock_skip_op_class = false;

        if (map_get_bw_from_op_class(op_class, &bw) || bw != 20) {
            continue;
        }

        if (map_get_band_from_op_class(op_class, &band)) {
            continue;
        }

        if (map_get_channel_set_from_op_class(op_class, &ch_set)) {
            continue;
        }

        /* Unset non operable channels */
        map_cs_and_not(&ch_set, &cap_op_class->channels);

        /* Check if op class must be ignored because of of 5G bandlock */
        if (is_5g_low_high && bandlock_5g != MAP_BANDLOCK_5G_DISABLED) {
            if ((bandlock_5g == MAP_BANDLOCK_5G_LOW  && !map_is_5g_low_op_class(op_class)) ||
                (bandlock_5g == MAP_BANDLOCK_5G_HIGH && !map_is_5g_high_op_class(op_class))) {
                bandlock_skip_op_class = true;
            }
        }

        /* Set all channels from operclass that are allowed by config... */
        map_cs_foreach(&ch_set, channel) {
            map_cs_set(&radio->cap_ctl_channels, channel);

            if (!bandlock_skip_op_class &&
                ((band == IEEE80211_FREQUENCY_BAND_2_4_GHZ && map_cs_is_set(&cfg->allowed_channel_set_2g, channel)) ||
                 (band == IEEE80211_FREQUENCY_BAND_5_GHZ   && map_cs_is_set(&cfg->allowed_channel_set_5g, channel)) ||
                 (band == IEEE80211_FREQUENCY_BAND_6_GHZ   && map_cs_is_set(&cfg->allowed_channel_set_6g, channel)))) {
                map_cs_set(&radio->ctl_channels, channel);
            }
        }
    }
}

static void map_update_radio_channels_with_bandwidth(map_radio_info_t *radio)
{
    map_chan_sel_cfg_t  *cfg               = &get_controller_cfg()->chan_sel;
    bool                 is_6g_psc         = (radio->supported_freq == BAND_6G) && cfg->allowed_channel_6g_psc;
    map_op_class_list_t *cap_op_class_list = &radio->cap_op_class_list;
    uint16_t             allowed_bandwidth = map_get_allowed_bandwidth(radio->supported_freq);
    int                  i;

    /* Create channel set per bandwidth using same logic as in set_controller_pref_op_class_list
       - check global allowed bandwidth
       - check global allowed channels and bandlock (use radio->ctl_channels set by map_update_radio_ctl_channels)
       - for bw > 20MHz: only allowed if all subband channels are set unless 6G PSC is configured
    */

    map_cs_bw_unset_all(&radio->channels_with_bandwidth);

    for (i = 0; i < cap_op_class_list->op_classes_nr; i++) {
        map_op_class_t    *cap_op_class = &cap_op_class_list->op_classes[i];
        uint8_t            op_class = cap_op_class->op_class;
        map_channel_set_t  ch_set;
        uint16_t           bw;
        uint8_t            channel;

        if (map_get_bw_from_op_class(op_class, &bw)) {
            continue;
        }

        if (map_get_channel_set_from_op_class(op_class, &ch_set)) {
            continue;
        }

        if (allowed_bandwidth > 0 && bw > allowed_bandwidth) {
            continue;
        }

        map_cs_and(&ch_set, &radio->ctl_channels);

        map_cs_foreach(&ch_set, channel) {
            if (!map_is_6G_320MHz_op_class(op_class)) {
                if (map_is_channel_in_cap_op_class(cap_op_class, channel)) {
                    if (bw == 20 || is_6g_psc || map_is_all_subband_channel_set(&radio->ctl_channels, op_class, channel)) {
                       map_cs_bw_set(&radio->channels_with_bandwidth, bw, channel);
                    }
                }
            } else {
                /* 6G 320MHz is special because it has 2 overlapping sets of channels -> check both */
                foreach_bool(upper) {
                    if (map_is_channel_in_cap_op_class_6G_320MHz(cap_op_class, upper, channel)) {
                        if (is_6g_psc || map_is_all_subband_channel_set_6G_320MHz(&radio->ctl_channels, op_class, upper, channel)) {
                           map_cs_bw_set(&radio->channels_with_bandwidth, bw, channel);
                        }
                    }
                }
            }
        }
    }
}

/*#######################################################################
#                       PUBLIC FUNCTIONS                                #
########################################################################*/
map_controller_cfg_t* get_controller_cfg()
{
    return &map_cfg_get()->controller_cfg;
}

uint16_t map_get_allowed_bandwidth(uint8_t band)
{
    map_chan_sel_cfg_t *cfg = &get_controller_cfg()->chan_sel;

    switch (band) {
        case BAND_2G: return cfg->allowed_bandwidth_2g;
        case BAND_5G: return cfg->allowed_bandwidth_5g;
        case BAND_6G: return cfg->allowed_bandwidth_6g;
        default:      return 0; /* Should not happen */
    }
}

void map_update_ale_receiving_iface(map_ale_info_t *ale, char* if_name)
{
    map_strlcpy(ale->iface_name, if_name, sizeof(ale->iface_name));

    /* For local agent, check if located next to controller */
    if (ale->is_local) {
        ale->is_local_colocated = map_is_loopback_iface(ale->iface_name);
    }
}

int parse_update_client_capability(map_sta_info_t *sta, uint16_t assoc_frame_len, uint8_t* assoc_frame)
{
    if (sta == NULL || assoc_frame_len == 0 || assoc_frame == NULL) {
        return -1;
    }

    /* Free the existing memory, and Alloc new memory for assoc_frame.
     * This will make sure, we will maintain one memory for assoc frame
     * irrespective of the function called multiple times for the same sta.
     */
    free(sta->assoc_frame);
    sta->assoc_frame_len = 0;

    /*
     *
     * Freeing of sta->assoc_frame is also taken care in remove_sta();
     * being called when sta disconnects from EBSS.
     *
     * If ever we don't need "sta->assoc_frame", we can free(sta->assoc_frame)
     * the memory and update the sta->assoc_frame_len = 0;
     */

    if (NULL == (sta->assoc_frame = malloc(assoc_frame_len))) {
        log_ctrl_e("failed to allocate assoc frame");
        return -1;
    }


    sta->assoc_frame_len = assoc_frame_len;
    memcpy(sta->assoc_frame, assoc_frame, assoc_frame_len);

    /* Fill in sta capabilities */
    map_80211_parse_assoc_body(&sta->sta_caps, sta->assoc_frame, sta->assoc_frame_len,
                               sta->bss->radio->supported_freq, (uint8_t*)sta->bss->ssid, sta->bss->ssid_len,
                               sta->sta_mld ? sta->mac : NULL);
    return 0;
}

/* Store assoc frame and parse it for each affiliated STA */
int parse_update_mld_client_capability(map_sta_mld_info_t *sta_mld, uint16_t assoc_frame_len, uint8_t* assoc_frame)
{
    if (sta_mld == NULL || assoc_frame_len == 0 || assoc_frame == NULL) {
        return -1;
    }

    free(sta_mld->assoc_frame);
    sta_mld->assoc_frame_len = 0;

    if (!(sta_mld->assoc_frame = malloc(assoc_frame_len))) {
        log_ctrl_e("failed to allocate assoc frame");
        return -1;
    }


    sta_mld->assoc_frame_len = assoc_frame_len;
    memcpy(sta_mld->assoc_frame, assoc_frame, assoc_frame_len);

    return parse_update_mld_aff_client_capability(sta_mld, true);
}

/* Parse stored assoc frame for each affiliated STA (for all when force is true) */
int parse_update_mld_aff_client_capability(map_sta_mld_info_t *sta_mld, bool force)
{
    map_sta_info_t *sta;

    if (sta_mld && sta_mld->assoc_frame) {
        map_mld_modes_t *m = &sta_mld->supported_mld_modes;
        /* Update capabilities for each affiliated STA and derive combined supported MLD modes
           NOTE: mark NSTR and !STR if at least one aff STA has NSTR
        */
        m->str = m->nstr = m->emlsr = m->emlmr = false;

        map_dm_foreach_aff_sta(sta_mld, sta) {
            if (force || !sta->assoc_frame) {
                parse_update_client_capability(sta, sta_mld->assoc_frame_len, sta_mld->assoc_frame);
            }

            m->str   |= sta->sta_caps.mld_modes.str;
            m->nstr  |= sta->sta_caps.mld_modes.nstr;
            m->emlsr |= sta->sta_caps.mld_modes.emlsr;
            m->emlmr |= sta->sta_caps.mld_modes.emlmr;
        }

        if (m->nstr) {
            m->str = false;
        }
    }

    return 0;
}

/** Function to recalculate the ale onboarding state based on current radio
    state(with MAP_ONBOARD_DEP_BITMASK in radio state) and updates the ALE
    onboarding state of respective ale in ale data model as well
*/
void map_recompute_radio_state_and_update_ale_state(map_ale_info_t *ale)
{
    map_radio_info_t     *radio;
    map_onboard_status_t  onboard_status = ALE_NODE_ONBOARDING;
    uint16_t              onboard_dep_bitmask;

    if (ale == NULL) {
        log_ctrl_e("invalid ale node onboarding state computation");
        return;
    }

    map_dm_foreach_radio(ale, radio) {
        onboard_dep_bitmask = is_radio_teardown_sent(radio->state) ? MAP_ONBOARD_DEP_BITMASK_TEARDOWN : MAP_ONBOARD_DEP_BITMASK;
        if ((radio->state & onboard_dep_bitmask) == onboard_dep_bitmask) {
            onboard_status = ALE_NODE_ONBOARDED;
            break;
        }
    }

    map_dm_ale_set_onboard_status(ale, onboard_status);
}

/* Function resets single ale node status to onboarding state(reset state) */
void map_reset_agent_node_onboarding_status(map_ale_info_t *ale)
{
    map_radio_info_t *radio;
    uint64_t    last_chan_sel_req = 0;

    /* REIMPLEMENT the channel selection request retrigger restriction logic to reset its state as per
        map_refresh_radio_data */
    if (ale->first_chan_sel_req_done) {
        last_chan_sel_req = acu_timestamp_delta_sec(ale->last_chan_sel_req_time);
    }

    map_dm_foreach_radio(ale, radio) {
        set_radio_state_policy_config_ack_not_received(&radio->state);
        set_radio_state_ap_cap_report_not_received(&radio->state);
        if (ale->first_chan_sel_req_done && last_chan_sel_req > 90) {
            set_radio_state_oper_chan_report_not_received(&radio->state);
            set_radio_state_channel_pref_report_not_received(&radio->state);
        }
        set_radio_state_unconfigured(&radio->state);
    }
    map_dm_ale_set_onboard_status(ale, ALE_NODE_ONBOARDING);
}

/* Function resets all ale node status to onboarding state(reset state)
   This can be due to any system level change in MAP implementation like renew etc.,
*/
void map_reset_all_agent_nodes_onboarding_status(void)
{
    map_ale_info_t   *ale;

    map_dm_foreach_agent_ale(ale) {
        map_reset_agent_node_onboarding_status(ale);
    }
}

uint64_t map_convert_mapunits_to_bytes(uint32_t val, uint8_t unit)
{
    uint64_t conv = val;

    if (unit == MAP_BYTE_COUNTER_UNIT_KIBI_BYTES) {
        conv = conv << 10;
    }

    if (unit == MAP_BYTE_COUNTER_UNIT_MEBI_BYTES) {
        conv = conv << 20;
    }

    return conv;
}

const char *map_scan_status_to_string(uint8_t scan_status)
{
    switch (scan_status) {
        case MAP_SCAN_STATUS_SUCCESS:               return "SUCCESS";
        case MAP_SCAN_STATUS_OPCLASS_NOT_SUPPORTED: return "NOT SUPPORTED";
        case MAP_SCAN_STATUS_TOO_SOON:              return "TOO SOON";
        case MAP_SCAN_STATUS_BUSY:                  return "BUSY";
        case MAP_SCAN_STATUS_NOT_COMPLETED:         return "NOT COMPLETED";
        case MAP_SCAN_STATUS_ABORTED:               return "ABORTED";
        case MAP_SCAN_STATUS_FRESH_NOT_SUPPORTED:   return "FRESH SCAN NOT SUPPORTED";
        default:                                    return "INVALID";
    }
}

const char* map_scan_type_to_string(uint8_t scan_type)
{
    switch (scan_type) {
        case MAP_SCAN_TYPE_PASSIVE: return "PASSIVE";
        case MAP_SCAN_TYPE_ACTIVE:  return "ACTIVE";
        default:                    return "INVALID";
    }
}

map_radio_info_t *map_find_radio_by_supported_channel(map_ale_info_t *ale, int channel)
{
    map_radio_info_t *radio;
    int               i;

    map_dm_foreach_radio(ale, radio) {
        for (i = 0; i < radio->cap_op_class_list.op_classes_nr; i++) {
            map_op_class_t *op_class = &radio->cap_op_class_list.op_classes[i];

            /* Channel in this op class and not in the non operable list */
            if (map_is_channel_in_op_class(op_class->op_class, channel) &&
                !map_cs_is_set(&op_class->channels, channel)) {
                return radio;
            }
        }
    }

    return NULL;
}

uint16_t map_get_freq_bands(map_radio_info_t *radio)
{
    if (radio->supported_freq == IEEE80211_FREQUENCY_BAND_2_4_GHZ) {
        return MAP_M2_BSS_RADIO2G;
    } else if(radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ) {
        return radio->band_type_5G & (MAP_M2_BSS_RADIO5GL | MAP_M2_BSS_RADIO5GU);
    } else if(radio->supported_freq == IEEE80211_FREQUENCY_BAND_6_GHZ) {
        return MAP_M2_BSS_RADIO6G;
    } else {
        return 0;
    }
}

bool map_is_5g_low_high(map_radio_info_t *radio)
{
    return (radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ) &&
           (radio->band_type_5G & MAP_M2_BSS_RADIO5GL) &&
           (radio->band_type_5G & MAP_M2_BSS_RADIO5GU);
}

bool map_is_radio_ap_mld_capable(map_ale_info_t *ale, map_radio_info_t *radio)
{
    map_mld_modes_t *m;

    return ((ale->agent_capability.max_mlds > 0) && (ale->agent_capability.ap_max_links > 0) &&
            ((m = radio->wifi7_caps ? &radio->wifi7_caps->ap_mld_modes : NULL)) &&
            (m->str || m->nstr || m->emlsr || m->emlsr));
}

bool map_is_radio_bsta_mld_capable(map_ale_info_t *ale, map_radio_info_t *radio)
{
    map_mld_modes_t *m;

    return ((ale->agent_capability.max_mlds > 0) && (ale->agent_capability.bsta_max_links > 0) &&
            (map_is_radio_bsta_capable(ale, radio->radio_id)) &&
            ((m = radio->wifi7_caps ? &radio->wifi7_caps->bsta_mld_modes : NULL)) &&
            (m->str || m->nstr || m->emlsr || m->emlsr));
}

/* Guess which profile was used to configure this bss - using same logic as in
   map_get_m2_config
*/
map_profile_cfg_t *map_get_profile_from_bss(map_bss_info_t *bss)
{
    map_controller_cfg_t *cfg = get_controller_cfg();
    map_ale_info_t       *ale;
    map_radio_info_t     *radio;
    uint16_t              freq_bands;
    bool                  is_gateway;
    size_t                i;

    if (!bss || !(radio = bss->radio) || !(ale = radio->ale)) {
        return NULL;
    }

    freq_bands = map_get_freq_bands(radio);
    is_gateway = map_is_local_agent(ale);

    for (i = 0; i < cfg->num_profiles; i++) {
        map_profile_cfg_t *profile = &cfg->profiles[i];
        int                ssid_len = strlen(profile->bss_ssid);

        if (!profile->enabled) {
            continue;
        }

        if (WFA_CERT() && memcmp(profile->al_mac, ale->al_mac, MAC_ADDR_LEN)) {
            continue;
        }

        if (ssid_len != bss->ssid_len || memcmp(profile->bss_ssid, bss->ssid, ssid_len)) {
            continue;
        }

        if ((is_gateway  && !profile->gateway) ||
            (!is_gateway && !profile->extender)) {
            continue;
        }

        if (!(profile->bss_freq_bands & freq_bands)) {
            continue;
        }

        /* FOUND */
        return profile;
    }

    return NULL;
}

/* Check if this radio has a profile with a wanted bss state (MAP_xxx_BSS).
   Using same logic as in map_get_m2_config.
*/
bool map_radio_has_profile_with_bss_state(map_radio_info_t *radio, uint8_t bss_state)
{
    map_controller_cfg_t *cfg = get_controller_cfg();
    map_ale_info_t       *ale;
    uint16_t              freq_bands;
    bool                  is_gateway;
    size_t                i;

    if (!radio || !(ale = radio->ale)) {
        return false;
    }

    freq_bands = map_get_freq_bands(radio);
    is_gateway = map_is_local_agent(ale);

    for (i = 0; i < cfg->num_profiles; i++) {
        map_profile_cfg_t *profile = &cfg->profiles[i];

        if (!profile->enabled) {
            continue;
        }

        if (WFA_CERT() && maccmp(profile->al_mac, ale->al_mac)) {
            continue;
        }

        if ((is_gateway  && !profile->gateway) ||
            (!is_gateway && !profile->extender)) {
            continue;
        }

        if (!(profile->bss_freq_bands & freq_bands)) {
            continue;
        }

        if (!(profile->bss_state & bss_state)) {
            continue;
        }

        /* FOUND */
        return true;
    }

    return false;
}

uint8_t *map_get_wsc_attr(uint8_t *message, uint16_t message_size, uint16_t attr_type, uint16_t *attr_len)
{
    uint8_t *p = message;

    while (p - message < message_size) {
        uint16_t t;

        _E2B(&p, &t);
        _E2B(&p, attr_len);

        if (t == attr_type) {
            return p;
        }
        p += *attr_len;
    }

    return NULL;
}

/* Check if channel is in op class and not its non operable list */
bool map_is_channel_in_cap_op_class(map_op_class_t *cap_op_class, uint8_t ctl_channel)
{
    uint8_t check_channel = ctl_channel;
    bool    is_center_channel;

    if (map_get_is_center_channel_from_op_class(cap_op_class->op_class, &is_center_channel)) {
        return false;  /* Error in oper class table... */
    }

    /* For 20 and 40MHz (2G and 5G) op classes -> beacon channel
       For for 40MHz (6G), 80, 160 and 320MHz op classes (128, 129, 130, 132, 133, 134, 137) -> center channel
    */
    if (is_center_channel && map_get_center_channel(cap_op_class->op_class, ctl_channel, &check_channel)) {
        return false;
    }

    if (map_is_channel_in_op_class(cap_op_class->op_class, check_channel) &&
        !map_cs_is_set(&cap_op_class->channels, check_channel)) {
        return true;
    }
    return false;
}

bool map_is_channel_in_cap_op_class_6G_320MHz(map_op_class_t *cap_op_class, bool upper, uint8_t ctl_channel)
{
    uint8_t center_channel;

    if (!map_is_6G_320MHz_op_class(cap_op_class->op_class)) {
        return false;
    }

    if (map_get_center_channel_6G_320MHz(cap_op_class->op_class, upper, ctl_channel, &center_channel)) {
        return false;
    }

    if (map_is_channel_in_op_class(cap_op_class->op_class, center_channel) &&
        !map_cs_is_set(&cap_op_class->channels, center_channel)) {
        return true;
    }
    return false;
}

uint8_t map_get_channel_pref(map_op_class_list_t *list, uint8_t op_class, uint8_t channel)
{
    return get_channel_pref(list, op_class, channel);
}

void map_update_radio_channels(map_radio_info_t *radio)
{
    map_update_radio_ctl_channels(radio);
    map_update_radio_channels_with_bandwidth(radio);
}

int map_merge_pref_op_class_list(map_op_class_list_t *merged_list, map_op_class_list_t *cap_list,
                                 map_op_class_list_t *list1, map_op_class_list_t *list2,
                                 map_op_class_list_t *disallowed_list)
{
    uint8_t disallowed_cnt = 0;
    uint8_t i;

    for (i = 0; i < disallowed_list->op_classes_nr; i++) {
        map_op_class_t *op_class = &disallowed_list->op_classes[i];

        if (op_class->enable == true && op_class->channels.nr > 0) {
            ++disallowed_cnt;
        }
    }

    merged_list->op_classes_nr = 0;

    /* Result cannot have more op_classes than the sum of list1 and list2 */
    merged_list->op_classes = calloc(list1->op_classes_nr + list2->op_classes_nr + disallowed_cnt, sizeof(map_op_class_t));
    if (!merged_list->op_classes) {
        return -1;
    }

    /* Add list 1 */
    merge_pref_op_class_list_add(merged_list, cap_list, list1, list2, disallowed_list);

    /* Add list 2 */
    merge_pref_op_class_list_add(merged_list, cap_list, list2, list1, disallowed_list);

    if (disallowed_cnt) {
        merge_disallowed_op_class_list_add(merged_list, cap_list, disallowed_list);
    }

    /* Clear channel lists when they contain all channels of an op class */
    map_optimize_pref_op_class_list(merged_list, cap_list);

    /* Sort op_classes and channels */
    map_sort_op_class_list(merged_list);

    return 0;
}

void map_optimize_pref_op_class_list(map_op_class_list_t *list, map_op_class_list_t *cap_list)
{
    map_channel_set_t ch_set;
    uint8_t           channel, i;
    bool              is_center_channel;

    for (i = 0; i < list->op_classes_nr; i++) {
        map_op_class_t *op_class = &list->op_classes[i];
        bool            all      = true;

        if (map_get_is_center_channel_from_op_class(op_class->op_class, &is_center_channel)) {
            continue;
        }

        if ((is_center_channel && map_get_center_channel_set_from_op_class(op_class->op_class, &ch_set)) ||
            (!is_center_channel && map_get_channel_set_from_op_class(op_class->op_class, &ch_set))) {
            continue;
        }

        map_cs_foreach(&ch_set, channel) {
            /* Skip static non operable channels */
            if (!is_channel_operable(cap_list, op_class->op_class, channel)) {
                continue;
            }

            if (!map_cs_is_set(&op_class->channels, channel)) {
                all = false;
            }
        }

        if (all) {
            map_cs_unset_all(&op_class->channels);
        }
    }
}

/* Given a op_class/channel combo, check if ALL of the corresponding 20MHz subband channels are UNSET in list
 * return TRUE if all 20MHz subband channels are UNSET set */
/* Given a op_class/channel combo, check if ALL of the corresponding 20MHz subband channels are UNSET in list
 * return TRUE if all 20MHz subband channels are UNSET set */
bool map_is_no_subband_channel_set(map_channel_set_t *channels, uint8_t op_class, uint8_t channel)
{
    uint8_t sub_chan, sub_from, sub_to;

    if (!map_get_subband_channel_range(op_class, channel, &sub_from, &sub_to)) {
        for (sub_chan = sub_from; sub_chan <= sub_to; sub_chan += 4) {
            if (map_cs_is_set(channels, sub_chan)) {
                return false;
            }
        }
    }

    return true;
}

/* Same as above but for 6G 320MHz */
bool map_is_no_subband_channel_set_6G_320MHz(map_channel_set_t *channels, uint8_t op_class, bool upper, uint8_t channel)
{
    uint8_t sub_chan, sub_from, sub_to;

    if (map_is_6G_320MHz_op_class(op_class) &&
        !map_get_subband_channel_range_6G_320MHz(op_class, upper, channel, &sub_from, &sub_to)) {
        for (sub_chan = sub_from; sub_chan <= sub_to; sub_chan += 4) {
            if (map_cs_is_set(channels, sub_chan)) {
                return false;
            }
        }
    }

    return true;
}

/* Given a op_class/channel combo, check if ALL corresponding 20MHz subband channels are SET in list */
/* return true if ALL 20MHz subband channels are SET */
/* NOTE: not applicable for 20MHz op_class */
bool map_is_all_subband_channel_set(map_channel_set_t *channels, uint8_t op_class, uint8_t channel)
{
    uint8_t sub_chan, sub_from, sub_to;

    if (!map_get_subband_channel_range(op_class, channel, &sub_from, &sub_to)) {
        /* iterate over all subband channels */
        /* for 2.4GHz: primary and secondary channel are also 4 channels separated from each other */
        for (sub_chan = sub_from; sub_chan <= sub_to; sub_chan += 4) {
            if (!map_cs_is_set(channels, sub_chan)) {
                return false;
            }
        }
    }

    return true;
}

/* Same as above but for 6G 320MHz */
bool map_is_all_subband_channel_set_6G_320MHz(map_channel_set_t *channels, uint8_t op_class, bool upper, uint8_t channel)
{
    uint8_t sub_chan, sub_from, sub_to;

    if (map_is_6G_320MHz_op_class(op_class) &&
        !map_get_subband_channel_range_6G_320MHz(op_class, upper, channel, &sub_from, &sub_to)) {
        for (sub_chan = sub_from; sub_chan <= sub_to; sub_chan += 4) {
            if (!map_cs_is_set(channels, sub_chan)) {
                return false;
            }
        }
    }

    return true;
}

void map_sort_op_class_list(map_op_class_list_t *list)
{
    qsort(list->op_classes, list->op_classes_nr, sizeof(map_op_class_t), comp_op_class);
}

bool map_is_cac_request_valid(map_radio_info_t *radio, uint8_t cac_method, uint8_t op_class, uint8_t channel)
{
    int8_t method_idx   = -1;
    int8_t op_class_idx = -1;
    int    i;

    /* Search method */
    for (i = 0; i < radio->cac_caps.cac_method_count; i++) {
        if (radio->cac_caps.cac_method[i].cac_method == cac_method) {
            method_idx = i;
            break;
        }
    }

    if (method_idx == -1) {
        log_ctrl_i("CAC request method[%u] is not valid for radio[%s]", cac_method, radio->radio_id_str);
        return false;
    }

    /* Search op_class */
    for (i = 0; i < radio->cac_caps.cac_method[method_idx].op_class_list.op_classes_nr; i++) {
        if (radio->cac_caps.cac_method[method_idx].op_class_list.op_classes[i].op_class == op_class) {
            op_class_idx = i;
            break;
        }
    }

    if (op_class_idx == -1) {
        log_ctrl_i("CAC request op_class[%u] is not valid for radio[%s]", op_class, radio->radio_id_str);
        return false;
    }

    /* Check channel */
    if (map_cs_is_set(&radio->cac_caps.cac_method[method_idx].op_class_list.op_classes[op_class_idx].channels, channel)) {
        return true;
    }

    log_ctrl_i("CAC request channel[%u] is not valid for radio[%s]", channel, radio->radio_id_str);

    return false;
}

map_local_iface_t *map_find_local_iface(map_ale_info_t *ale, mac_addr mac)
{
    size_t i;

    for (i = 0; i < ale->local_iface_count; i++) {
        map_local_iface_t *iface = &ale->local_iface_list[i];

        if (!maccmp(iface->mac_address, mac)) {
            return iface;
        }
    }

    return NULL;
}

bool map_is_radio_bsta_capable(map_ale_info_t *ale, mac_addr radio_id)
{
    size_t i;

    for (i = 0; i < ale->backhaul_sta_iface_count; i++) {
        map_backhaul_sta_iface_t *bhsta_iface = &ale->backhaul_sta_iface_list[i];
        if (bhsta_iface && !maccmp(bhsta_iface->radio_id, radio_id)) {
            return true;
        }
    }

    return false;
}

map_backhaul_sta_iface_t *map_find_bhsta_iface_from_ale(map_ale_info_t *ale, mac_addr sta_mac)
{
    size_t i;

    for (i = 0; i < ale->backhaul_sta_iface_count; i++) {
        map_backhaul_sta_iface_t *bhsta_iface = &ale->backhaul_sta_iface_list[i];
        if (bhsta_iface && !maccmp(bhsta_iface->mac_address, sta_mac)) {
            return bhsta_iface;
        }
    }

    return NULL;
}

map_backhaul_sta_iface_t *map_find_bhsta_iface_gbl(mac_addr sta_mac, map_ale_info_t **ret_ale)
{
    map_ale_info_t              *ale;
    map_backhaul_sta_iface_t    *bhsta_iface;

    map_dm_foreach_agent_ale(ale) {
        if ((bhsta_iface = map_find_bhsta_iface_from_ale(ale, sta_mac))) {
            if (ret_ale) {
                *ret_ale = ale;
            }
            return bhsta_iface;
        }
    }

    return NULL;
}

void map_free_ht_vht_he_wifi6_caps(map_radio_info_t *radio)
{
    SFREE(radio->ht_caps);
    SFREE(radio->vht_caps);
    SFREE(radio->he_caps);
    SFREE(radio->wifi6_caps);

}

void map_free_wifi7_caps(map_radio_info_t *radio)
{
    if (radio->wifi7_caps) {
        SFREE(radio->wifi7_caps->ap_str_records);
        SFREE(radio->wifi7_caps->ap_nstr_records);
        SFREE(radio->wifi7_caps->ap_emlsr_records);
        SFREE(radio->wifi7_caps->ap_emlmr_records);
        SFREE(radio->wifi7_caps->bsta_str_records);
        SFREE(radio->wifi7_caps->bsta_nstr_records);
        SFREE(radio->wifi7_caps->bsta_emlsr_records);
        SFREE(radio->wifi7_caps->bsta_emlmr_records);
        SFREE(radio->wifi7_caps);
    }

}

void map_update_radio_caps(map_radio_info_t *radio)
{
    /* Use HT and VHT cap to fill in global caps */
    map_radio_capability_t     *caps     = &radio->radio_caps;
    map_radio_vht_capability_t *vht_caps = radio->vht_caps;
    map_radio_ht_capability_t  *ht_caps  = radio->ht_caps;
    map_radio_he_capability_t  *he_caps  = radio->he_caps;
    map_radio_eht_capability_t *eht_caps = radio->eht_caps;
    bool                        is_2g    = radio->supported_freq == IEEE80211_FREQUENCY_BAND_2_4_GHZ;
    bool                        is_5g    = radio->supported_freq == IEEE80211_FREQUENCY_BAND_5_GHZ;
    bool                        is_6g    = radio->supported_freq == IEEE80211_FREQUENCY_BAND_6_GHZ;

    /* Standard (forget about 11B) */

    if (is_6g) {
        caps->supported_standard = eht_caps ? STD_80211_BE : STD_80211_AX;
    } else if (is_5g) {
        caps->supported_standard = (he_caps && vht_caps && ht_caps) ? STD_80211_ANACAX :
                                   (he_caps && vht_caps) ? STD_80211_ACAX :
                                   (he_caps && ht_caps) ? STD_80211_ANAX :
                                   (vht_caps) ? STD_80211_AC :
                                   (ht_caps) ? STD_80211_N : STD_80211_A;
    } else { /* 2.4ghz */
        caps->supported_standard = he_caps ? STD_80211_NAX :
                                   ht_caps ? STD_80211_N : STD_80211_G;
    }

    /* Defaults */
    caps->max_tx_spatial_streams = 1;
    caps->max_rx_spatial_streams = 1;
    caps->max_bandwidth          = 20;
    caps->sgi_support            = 0;
    caps->su_beamformer_capable  = 0;
    caps->mu_beamformer_capable  = 0;
    caps->dl_ofdma               = 0;
    caps->ul_ofdma               = 0;

    /* Caps: use most advanced info */
    if (he_caps) {
        caps->max_tx_spatial_streams = he_caps->max_supported_tx_streams;
        caps->max_rx_spatial_streams = he_caps->max_supported_rx_streams;
        if (!is_2g) {
            caps->max_bandwidth      = (he_caps->support_80_80_mhz || he_caps->support_160mhz) ||
                                       (vht_caps && (vht_caps->support_80_80_mhz || vht_caps->support_160mhz)) ? 160 : 80;
        } else {
            caps->max_bandwidth      = (ht_caps && ht_caps->ht_support_40mhz) ? 40 : 20;
        }
        caps->su_beamformer_capable  = he_caps->su_beamformer_capable;
        caps->mu_beamformer_capable  = he_caps->mu_beamformer_capable;
        caps->dl_ofdma               = he_caps->dl_ofdma_capable;
        caps->ul_ofdma               = he_caps->ul_ofdma_capable;
    } else if (!is_2g && vht_caps) {
        caps->max_tx_spatial_streams = vht_caps->max_supported_tx_streams;
        caps->max_rx_spatial_streams = vht_caps->max_supported_rx_streams;
        caps->max_bandwidth          = vht_caps->support_80_80_mhz || vht_caps->support_160mhz ? 160 : 80;
        caps->su_beamformer_capable  = vht_caps->su_beamformer_capable;
        caps->mu_beamformer_capable  = vht_caps->mu_beamformer_capable;
    } else if (ht_caps) {
        caps->max_tx_spatial_streams = ht_caps->max_supported_tx_streams;
        caps->max_rx_spatial_streams = ht_caps->max_supported_rx_streams;
        caps->max_bandwidth          = ht_caps->ht_support_40mhz ? 40 : 20;
    }

    if (is_6g && eht_caps) {
        caps->max_bandwidth = 320; /* TODO this is an assumption for eth capable radios
                                    * Fill caps properly when eht_caps are filled.
                                    */
    }

    /* Set SGI from HE, VHT/HT */
    if (!is_2g && vht_caps) {
        caps->sgi_support = vht_caps->gi_support_160mhz || vht_caps->gi_support_80mhz;
    } else if (ht_caps) {
        caps->sgi_support = ht_caps->gi_support_40mhz || ht_caps->gi_support_20mhz;
    }
}

bool map_is_non_bss_ap_mld_or_sta_mld(map_ale_info_t *ale, mac_addr bssid, mac_addr sta_mac)
{
    /* Return true when
       - MLD AP found and it is no regular BSS
       - OR MLD STA found
    */

    return map_dm_ale_has_mld(ale) &&
           ((bssid && map_dm_get_ap_mld(ale, bssid) && !map_dm_get_bss_from_ale(ale, bssid)) ||
            (sta_mac && map_dm_get_sta_mld_from_ale(ale, sta_mac)));
}

map_sta_info_t *map_get_aff_sta_from_band(map_sta_mld_info_t *sta_mld, uint8_t band)
{
    map_sta_info_t *sta;

    map_dm_foreach_aff_sta(sta_mld, sta) {
        if (sta->bss->radio->supported_freq == band) {
            return sta;
        }
    }

    return NULL;
}

map_sta_info_t *map_get_aff_sta_first(map_sta_mld_info_t *sta_mld)
{
    return (sta_mld->aff_sta_nr > 0) ? list_first_entry(&sta_mld->aff_sta_list, map_sta_info_t, aff_sta_list) : NULL;
}
