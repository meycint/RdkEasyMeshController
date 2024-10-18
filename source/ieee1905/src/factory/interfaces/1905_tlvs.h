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

/*
 *  Broadband Forum IEEE 1905.1/1a stack
 *
 *  Copyright (c) 2017, Broadband Forum
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  Subject to the terms and conditions of this license, each copyright
 *  holder and contributor hereby grants to those receiving rights under
 *  this license a perpetual, worldwide, non-exclusive, no-charge,
 *  royalty-free, irrevocable (except for failure to satisfy the
 *  conditions of this license) patent license to make, have made, use,
 *  offer to sell, sell, import, and otherwise transfer this software,
 *  where such license applies only to those patent claims, already
 *  acquired or hereafter acquired, licensable by such copyright holder or
 *  contributor that are necessarily infringed by:
 *
 *  (a) their Contribution(s) (the licensed copyrights of copyright holders
 *      and non-copyrightable additions of contributors, in source or binary
 *      form) alone; or
 *
 *  (b) combination of their Contribution(s) with the work of authorship to
 *      which such Contribution(s) was added by such copyright holder or
 *      contributor, if, at the time the Contribution is added, such addition
 *      causes such combination to be necessarily infringed. The patent
 *      license shall not apply to any other combinations which include the
 *      Contribution.
 *
 *  Except as expressly stated above, no rights or licenses from any
 *  copyright holder or contributor is granted under this license, whether
 *  expressly, by implication, estoppel or otherwise.
 *
 *  DISCLAIMER
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 *  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 */

#ifndef _1905_TLVS_H_
#define _1905_TLVS_H_

#include "platform.h"

#include "packet_tools.h"
/* In the comments below, every time a reference is made (ex: "See Section 6.4"
*  or "See Table 6-11") we are talking about the contents of the following
*  document:
*
*  "IEEE Std 1905.1-2013"
*/

/*#######################################################################
# TLV types as detailed in "Section 6.4"                                #
########################################################################*/
#define TLV_TYPE_END_OF_MESSAGE                      (0)
#define TLV_TYPE_AL_MAC_ADDRESS                      (1)
#define TLV_TYPE_MAC_ADDRESS                         (2)
#define TLV_TYPE_DEVICE_INFORMATION                  (3)
#define TLV_TYPE_DEVICE_BRIDGING_CAPABILITY          (4)
#define TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST       (6)
#define TLV_TYPE_NEIGHBOR_DEVICE_LIST                (7)
#define TLV_TYPE_LINK_METRIC_QUERY                   (8)
#define TLV_TYPE_TRANSMITTER_LINK_METRIC             (9)
#define TLV_TYPE_RECEIVER_LINK_METRIC                (10)
#define TLV_TYPE_VENDOR_SPECIFIC                     (11)
#define TLV_TYPE_LINK_METRIC_RESULT_CODE             (12)
#define TLV_TYPE_SEARCHED_ROLE                       (13)
#define TLV_TYPE_AUTOCONFIG_FREQ_BAND                (14)
#define TLV_TYPE_SUPPORTED_ROLE                      (15)
#define TLV_TYPE_SUPPORTED_FREQ_BAND                 (16)
#define TLV_TYPE_WSC                                 (17)
#define TLV_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION      (18)
#define TLV_TYPE_PUSH_BUTTON_JOIN_NOTIFICATION       (19)
#define TLV_TYPE_GENERIC_PHY_DEVICE_INFORMATION      (20)
#define TLV_TYPE_DEVICE_IDENTIFICATION               (21)
#define TLV_TYPE_CONTROL_URL                         (22)
#define TLV_TYPE_IPV4                                (23)
#define TLV_TYPE_IPV6                                (24)
#define TLV_TYPE_GENERIC_PHY_EVENT_NOTIFICATION      (25)
#define TLV_TYPE_1905_PROFILE_VERSION                (26)
#define TLV_TYPE_POWER_OFF_INTERFACE                 (27)
#define TLV_TYPE_INTERFACE_POWER_CHANGE_INFORMATION  (28)
#define TLV_TYPE_INTERFACE_POWER_CHANGE_STATUS       (29)
#define TLV_TYPE_L2_NEIGHBOR_DEVICE                  (30)

#define TLV_TYPE_LAST                                (30)
                                                     /* NOTE: If new types are introduced in future
                                                     *  revisions of the standard, update this
                                                     *  value so that it always points to the last one.
                                                     */

#define TLV_TYPE_UNKNOWN                             (0xFF)

/*#######################################################################
# Media types as detailed in "Table 6-12"                               #
########################################################################*/
#define MEDIA_TYPE_IEEE_802_3U_FAST_ETHERNET       (0x0000)
#define MEDIA_TYPE_IEEE_802_3AB_GIGABIT_ETHERNET   (0x0001)
#define MEDIA_TYPE_IEEE_802_11B_2_4_GHZ            (0x0100)
#define MEDIA_TYPE_IEEE_802_11G_2_4_GHZ            (0x0101)
#define MEDIA_TYPE_IEEE_802_11A_5_GHZ              (0x0102)
#define MEDIA_TYPE_IEEE_802_11N_2_4_GHZ            (0x0103)
#define MEDIA_TYPE_IEEE_802_11N_5_GHZ              (0x0104)
#define MEDIA_TYPE_IEEE_802_11AC_5_GHZ             (0x0105)
#define MEDIA_TYPE_IEEE_802_11AD_60_GHZ            (0x0106)
#define MEDIA_TYPE_IEEE_802_11AF                   (0x0107)
#define MEDIA_TYPE_IEEE_802_11AX                   (0x0108) /* MAP R2 extension. One value all bands */
#define MEDIA_TYPE_IEEE_802_11BE                   (0x0109) /* MAP R6 extension. One value all bands */
#define MEDIA_TYPE_IEEE_1901_WAVELET               (0x0200)
#define MEDIA_TYPE_IEEE_1901_FFT                   (0x0201)
#define MEDIA_TYPE_MOCA_V1_1                       (0x0300)
#define MEDIA_TYPE_UNKNOWN                         (0xFFFF)

/*#######################################################################
# IEEE802.11 frequency bands used in "Tables 6-22 and 6-24"             #
########################################################################*/
#define IEEE80211_ROLE_REGISTRAR                   (0x00)

/*#######################################################################
# IEEE802.11 frequency bands used in "Tables 6-23 and 6-25"             #
########################################################################*/
/* TODO: also defined in map_common_defines.h */
#ifndef IEEE80211_FREQUENCY_BAND_2_4_GHZ
  #define IEEE80211_FREQUENCY_BAND_2_4_GHZ           (0x00)
  #define IEEE80211_FREQUENCY_BAND_5_GHZ             (0x01)
  #define IEEE80211_FREQUENCY_BAND_60_GHZ            (0x02)
  #define IEEE80211_FREQUENCY_BAND_6_GHZ             (0x03)
  #define IEEE80211_FREQUENCY_BAND_UNKNOWN           (0xFF)
#endif

/*#######################################################################
# Media type structures detailed in "Tables 6-12 and 6-13"              #
########################################################################*/
typedef struct _ieee80211SpecificInformation {
    mac_addr network_membership; /* BSSID */

    #define IEEE80211_SPECIFIC_INFO_ROLE_AP                   (0x0)
    #define IEEE80211_SPECIFIC_INFO_ROLE_NON_AP_NON_PCP_STA   (0x4)
    #define IEEE80211_SPECIFIC_INFO_ROLE_WIFI_P2P_CLIENT      (0x8)
    #define IEEE80211_SPECIFIC_INFO_ROLE_WIFI_P2P_GROUP_OWNER (0x9)
    #define IEEE80211_SPECIFIC_INFO_ROLE_AD_PCP               (0xa)
    uint8_t  role;               /* One of the values from above */

    uint8_t  ap_channel_band;    /* Hex value of dot11CurrentChannelBandwidth
                                 *  (see "IEEE P802.11ac/D3.0" for description)
                                 */

    uint8_t  ap_channel_center_frequency_index_1;
                                 /* Hex value of
                                 *  dot11CurrentChannelCenterFrequencyIndex1
                                 *  (see "IEEE P802.11ac/D3.0" for description)
                                 */

    uint8_t  ap_channel_center_frequency_index_2;
                                 /* Hex value of
                                 *  dot11CurrentChannelCenterFrequencyIndex2
                                 *  (see "IEEE P802.11ac/D3.0" for description)
                                 */
} i1905_ieee80211_specific_information_t;

typedef struct _ieee1901SpecificInformation {
    uint8_t network_identifier[7];  /* Network membership */
} i190t_ieee1905_specific_information_t;

typedef union _mediaSpecificData {
    uint8_t                              dummy;    /* Empty placeholder */
    struct _ieee80211SpecificInformation ieee80211;
    struct _ieee1901SpecificInformation  ieee1901;

} i1905_media_specific_data_t;

typedef struct wscKey {
    uint8_t  *key;
    uint32_t  key_len;
    mac_addr  mac;
} i1905_wsc_key_t;

/*#######################################################################
# Generic phy common structure used in "Tables 6.29, 6.36 and 6.38"     #
########################################################################*/
typedef struct _genericPhyCommonData {
    uint8_t  oui[3];                  /* OUI of the generic phy networking
                                      *  technology of the local interface
                                      */

    uint8_t  variant_index;           /* Variant index of the generic phy
                                      *  networking technology of the local
                                      *  interface
                                      */

    uint8_t  media_specific_bytes_nr;
    uint8_t *media_specific_bytes;    /* Media specific information of the
                                      *  variant.
                                      *  This field contains
                                      *  "media_specific_bytes_nr" bytes.
                                      */
} i1905_generic_phy_common_data_t;

/*#######################################################################
# End of message TLV associated structures ("Section 6.4.1")            #
########################################################################*/
typedef struct endOfMessageTLV {
    uint8_t tlv_type;             /* Must always be set to TLV_TYPE_END_OF_MESSAGE */

    /* This structure does not contain anything at all */
} i1905_end_of_message_tlv_t;

/*#######################################################################
# Vendor specific TLV associated structures ("Section 6.4.2")           #
########################################################################*/
typedef struct vendorSpecificTLV {
    uint8_t   tlv_type;           /* Must always be set to TLV_TYPE_VENDOR_SPECIFIC */

    uint8_t   vendorOUI[3];       /* Vendor specific OUI, the value of the 24
                                  *  bit globally unique IEEE-SA assigned number
                                  *  to the vendor
                                  */

    uint16_t  m_nr;               /* Bytes in the following field */
    uint8_t  *m;                  /* Vendor specific information */
} i1905_vendor_specific_tlv_t;

/*#######################################################################
# AL MAC address TLV associated structures ("Section 6.4.3")            #
########################################################################*/
typedef struct alMacAddressTypeTLV {
    uint8_t  tlv_type;            /* Must always be set to TLV_TYPE_AL_MAC_ADDRESS */

    mac_addr al_mac_address;      /* 1905 AL MAC address of the transmitting device */
} i1905_al_mac_address_tlv_t;

/*#######################################################################
# MAC address TLV associated structures ("Section 6.4.4")               #
########################################################################*/
typedef struct macAddressTypeTLV {
    uint8_t  tlv_type;            /* Must always be set to TLV_TYPE_MAC_ADDRESS */

    mac_addr mac_address;         /* MAC address of the interface on which the
                                  *  message is transmitted
                                  */
} i1905_mac_address_tlv_t;

/*#######################################################################
# Device information TLV associated structures ("Section 6.4.5")        #
########################################################################*/
typedef struct _localInterfaceEntries {
    mac_addr mac_address;         /* MAC address of the local interface */

    uint16_t media_type;          /* One of the MEDIA_TYPE_* values */

    uint8_t  media_specific_data_size;
                                  /* Number of bytes in ensuing field
                                  *  Its value is '10' when 'media_type' is one
                                  *  of the valid MEDIA_TYPE_IEEE_802_11* values.
                                  *  Its value is '7' when 'media_type' is one
                                  *  of the valid MEDIA_TYPE_IEEE_1901* values.
                                  */

    i1905_media_specific_data_t media_specific_data;
                                  /* Media specific data
                                  *  It will contain a IEEE80211 structure
                                  *  when 'media_type' is one of the valid
                                  *  MEDIA_TYPE_IEEE_802_11* values
                                  *  It will contain a IEE1905 structure
                                  *  when 'media_type' is one of the valid
                                  *  MEDIA_TYPE_IEEE_1901* values
                                  *  It will be empty in the rest of cases
                                  */

} i1905_local_interface_entry_t;

typedef struct deviceInformationTypeTLV {
    uint8_t  tlv_type;            /* Must always be set to TLV_TYPE_DEVICE_INFORMATION */

    mac_addr al_mac_address;      /* 1905 AL MAC address of the device */

    uint8_t  local_interfaces_nr; /* Number of local interfaces */

    i1905_local_interface_entry_t *local_interfaces;

} i1905_device_information_tlv_t;

/*########################################################################
# Device bridging capability TLV associated structures ("Section 6.4.6") #
#########################################################################*/
typedef struct _bridgingTupleMacEntries {
    mac_addr mac_address;         /* MAC address of a 1905 device's network
                                  *  interface that belongs to a bridging tuple
                                  */
} i1905_bridging_tuple_mac_entry_t;

typedef struct _bridgingTupleEntries
{
    uint8_t bridging_tuple_macs_nr; /* Number of MAC addresses in this bridging tuple */

    i1905_bridging_tuple_mac_entry_t *bridging_tuple_macs;
                                    /* List of 'mac_nr' elements, each one
                                    *  representing a MAC. All these MACs are
                                    *  bridged together.
                                    */
} i1905_bridging_tuple_entry_t;

typedef struct deviceBridgingCapabilityTLV {
    uint8_t   tlv_type;           /* Must always be set to TLV_TYPE_DEVICE_BRIDGING_CAPABILITIES */

    uint8_t   bridging_tuples_nr; /* Number of MAC addresses in this bridging tuple */

    i1905_bridging_tuple_entry_t *bridging_tuples;
} i1905_device_bridging_cap_tlv_t;

/*###########################################################################
# Non-1905 neighbor device list TLV associated structures ("Section 6.4.8") #
############################################################################*/
typedef struct _non1905neighborEntries {
    mac_addr mac_address;        /* MAC address of the non-1905 device */
} i1905_non_1905_neighbor_entry_t;

typedef struct non1905NeighborDeviceListTLV
{
    uint8_t  tlv_type;            /* Must always be set to TLV_TYPE_NON_1905_NEIGHBOR_DEVICE_LIST */

    mac_addr local_mac_address;   /* MAC address of the local interface */

    uint8_t                          non_1905_neighbors_nr;
    i1905_non_1905_neighbor_entry_t *non_1905_neighbors;
                                  /* One entry for each non-1905 detected neighbor */
} i1905_non_1905_neighbor_device_list_tlv_t;

/*#######################################################################
# Neighbor device TLV associated structures ("Section 6.4.9")           #
########################################################################*/
typedef struct _neighborEntries {
    mac_addr mac_address;         /* AL MAC address of the 1905 neighbor */

    uint8_t  bridge_flag;         /* "0" --> no IEEE 802.1 bridge exists
                                  *  "1" --> at least one IEEE 802.1 bridge
                                  *          exists between this device and the neighbor
                                  */
} i1905_neighbor_entry_t;

typedef struct neighborDeviceListTLV {
    uint8_t  tlv_type;            /* Must always be set to TLV_TYPE_NEIGHBOR_DEVICE_LIST */

    mac_addr local_mac_address;   /* MAC address of the local interface */

    uint8_t                 neighbors_nr;
    i1905_neighbor_entry_t *neighbors;
                                  /* One entry for each 1905 detected neighbor */
} i1905_neighbor_device_list_tlv_t;

/*#######################################################################
# Link metric query TLV associated structures ("Section 6.4.10")        #
########################################################################*/
typedef struct linkMetricQueryTLV {
    uint8_t   tlv_type;           /* Must always be set to TLV_TYPE_LINK_METRIC_QUERY */

    #define LINK_METRIC_QUERY_TLV_ALL_NEIGHBORS      (0x00)
    #define LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR  (0x01)
    uint8_t  destination;         /* One of the values from above */

    mac_addr specific_neighbor;   /* Only significant when the 'destination'
                                  *  field is set to
                                  *  'LINK_METRIC_QUERY_TLV_SPECIFIC_NEIGHBOR'
                                  */

    #define LINK_METRIC_QUERY_TLV_TX_LINK_METRICS_ONLY         (0x00)
    #define LINK_METRIC_QUERY_TLV_RX_LINK_METRICS_ONLY         (0x01)
    #define LINK_METRIC_QUERY_TLV_BOTH_TX_AND_RX_LINK_METRICS  (0x02)
    uint8_t  link_metrics_type;   /* One of the values from above */
} i1905_link_metric_query_tlv_t;

/*#######################################################################
# Transmitter link metric TLV associated structures ("Section 6.4.11")  #
########################################################################*/
typedef struct _transmitterLinkMetricEntries {
    mac_addr local_interface_address;    /* MAC address of an interface in
                                         *  the receiving AL, which connects
                                         *  to an interface in the neighbor AL
                                         */

    mac_addr neighbor_interface_address; /* MAC addres of an interface in a
                                         *  neighbor AL, which connects to
                                         * an interface in the receiving AL
                                         */

    uint16_t intf_type;                  /* Underlaying network technology
                                         *  One of the MEDIA_TYPE_* values.
                                         */

    uint8_t  bridge_flag;                /* Indicates whether or not the 1905 link
                                         *  includes one or more IEEE 802.11 bridges
                                         */

    uint32_t packet_errors;              /* Estimated number of lost packets on the
                                         *  transmitting side of the link during
                                         *  the measurement period (5 seconds??)
                                         */

    uint32_t transmitted_packets;        /* Estimated number of packets transmitted
                                         *  on the same measurement period used to
                                         *  estimate 'packet_errors'
                                         */

    uint16_t mac_throughput_capacity;    /* The maximum MAC throughput of the link
                                         *  estimated at the transmitter and
                                         *  expressed in Mb/s
                                         */

    uint16_t link_availability;          /* The estimated average percentage of
                                         *  time that the link is available for
                                         *  data transmissions
                                         */

    uint16_t phy_rate;                   /* This value is the PHY rate estimated at
                                         *  the transmitter of the link expressed in Mb/s
                                         */
} i1905_transmitter_link_metric_entry_t;

typedef struct transmitterLinkMetricTLV {
    uint8_t  tlv_type;            /* Must always be set to TLV_TYPE_TRANSMITTER_LINK_METRIC */

    mac_addr local_al_address;    /* AL MAC address of the device that
                                  *  transmits the response message that
                                  *  contains this TLV
                                  */

    mac_addr neighbor_al_address; /* AL MAC address of the neighbor whose
                                  *  link metric is reported in this TLV
                                  */

    uint8_t                                transmitter_link_metrics_nr;
    i1905_transmitter_link_metric_entry_t *transmitter_link_metrics;
                                  /* Link metric information for the above
                                  *  interface pair between the receiving AL
                                  *  and the neighbor AL
                                  */
} i1905_transmitter_link_metric_tlv_t;

/*#######################################################################
# Receiver link metric TLV associated structures ("Section 6.4.12")     #
########################################################################*/
typedef struct _receiverLinkMetricEntries {
    mac_addr local_interface_address;    /* MAC address of an interface in
                                         *  the receiving AL, which connects
                                         *  to an interface in the neighbor AL
                                         */

    mac_addr neighbor_interface_address; /* MAC addres of an interface in a
                                         *  neighbor AL, which connects to
                                         *  an interface in the receiving AL
                                         */

    uint16_t intf_type;                  /* Underlaying network technology */

    uint32_t packet_errors;              /* Estimated number of lost packets on the
                                         *  receiving side of the link during
                                         *  the measurement period (5 seconds??)
                                         */

    uint32_t packets_received;           /* Estimated number of packets received on
                                         *  the same measurement period used to
                                         *  estimate 'packet_errors'
                                         */

    uint8_t  rssi;                      /* This value is the estimated RSSI at the
                                        *  receive side of the link expressed in dB
                                        */
} i1905_receiver_link_metric_entry_t;

typedef struct receiverLinkMetricTLV {
    uint8_t   tlv_type;           /* Must always be set to TLV_TYPE_RECEIVER_LINK_METRIC */

    mac_addr local_al_address;    /* AL MAC address of the device that
                                  *  transmits the response message that
                                  *  contains this TLV
                                  */

    mac_addr neighbor_al_address; /* AL MAC address of the neighbor whose
                                  *  link metric is reported in this TLV
                                  */

    uint8_t                             receiver_link_metrics_nr;
    i1905_receiver_link_metric_entry_t *receiver_link_metrics;
                                  /* Link metric information for the above
                                  *  interface pair between the receiving AL
                                  *  and the neighbor AL
                                  */
} i1905_receiver_link_metric_tlv_t;

/*#######################################################################
# Link metric result code TLV associated structures ("Section 6.4.13")  #
########################################################################*/
typedef struct linkMetricResultCodeTLV {
    uint8_t tlv_type;             /* Must always be set to TLV_TYPE_LINK_METRIC_RESULT_CODE */

    #define LINK_METRIC_RESULT_CODE_TLV_INVALID_NEIGHBOR  (0x00)
    uint8_t result_code;          /* One of the values from above */
} i1905_link_metric_result_code_tlv_t;

/*#######################################################################
# Searched role TLV associated structures ("Section 6.4.14")            #
########################################################################*/
typedef struct searchedRoleTLV
{
    uint8_t tlv_type;             /* Must always be set to TLV_TYPE_SEARCHED_ROLE */

    uint8_t role;                 /* One of the values from IEEE80211_ROLE_* */
} i1905_searched_role_tlv_t;

/*########################################################################
# Autoconfig frequency band TLV associated structures ("Section 6.4.15") #
#########################################################################*/
typedef struct autoconfigFreqBandTLV {
    uint8_t tlv_type;             /* Must always be set to TLV_TYPE_AUTOCONFIG_FREQ_BAND */

    uint8_t freq_band;            /* Frequency band of the unconfigured
                                  *  interface requesting an autoconfiguration.
                                  *  Use one of the values in IEEE80211_FREQUENCY_BAND_*
                                  */
} i1905_autoconfig_freq_band_tlv_t;

/*#######################################################################
 # Supported role TLV associated structures ("Section 6.4.16")          #
########################################################################*/
typedef struct supportedRoleTLV
{
    uint8_t tlv_type;             /* Must always be set to TLV_TYPE_SUPPORTED_ROLE */

    uint8_t role;                 /* One of the values from IEEE80211_ROLE_* */
} i1905_supported_role_tlv_t;

/*#######################################################################
# Supported frequency band TLV associated structures ("Section 6.4.17") #
########################################################################*/
typedef struct supportedFreqBandTLV {
    uint8_t tlv_type;             /* Must always be set to TLV_TYPE_SUPPORTED_FREQ_BAND */

    uint8_t freq_band;            /* Frequency band of the unconfigured
                                  *  interface requesting an autoconfiguration.
                                  *  Use one of the values in IEEE80211_FREQUENCY_BAND_*
                                  */
} i1905_supported_freq_band_tlv_t;

/*#######################################################################
# WSC TLV associated structures ("Section 6.4.18")                      #
########################################################################*/
/* Attributes used outside al_wsc.c */
#define WSC_ATTR_AUTH_TYPE_FLAGS  (0x1004)
#define WSC_ATTR_MAC_ADDR         (0x1020)
#define WSC_ATTR_MANUFACTURER     (0x1021)
#define WSC_ATTR_MODEL_NAME       (0x1023)
#define WSC_ATTR_MODEL_NUMBER     (0x1024)
#define WSC_ATTR_SERIAL_NUMBER    (0x1042)
#define WSC_ATTR_OS_VERSION       (0x102d)
#define WSC_ATTR_VENDOR_EXTENSION (0x1049)

/* Flags for MultiAp extension subelement  */
#define WSC_WFA_MAP_ATTR_FLAG_BACKHAUL_BSS  (0x40) /* Bit 6 */
#define WSC_WFA_MAP_ATTR_FLAG_FRONTHAUL_BSS (0x20) /* Bit 5 */
#define WSC_WFA_MAP_ATTR_FLAG_TEARDOWN      (0x10) /* Bit 4 */

typedef struct wscTLV {
    uint8_t   tlv_type;           /* Must always be set to TLV_TYPE_WSC */

    uint16_t  wsc_frame_size;
    uint8_t  *wsc_frame;          /*Pointer to a buffer containing the M1 or M2 message */
} i1905_wsc_tlv_t;

/*#############################################################################
# Push button event notification TLV associated structures ("Section 6.4.19") #
##############################################################################*/
typedef struct _mediaTypeEntries {
    uint16_t media_type;          /* A media type for which a push button
                                  *  configuration method has been activated on
                                  *  the device that originates the push button
                                  *  event notification
                                  *  One of the MEDIA_TYPE_* values
                                  */

    uint8_t  media_specific_data_size; /* Number of bytes in ensuing field */

    i1905_media_specific_data_t media_specific_data;
                                  /* Media specific data
                                  *  It will contain a IEEE80211 structure
                                  *  when 'media_type' is one of the valid
                                  *  MEDIA_TYPE_IEEE_802_11* values
                                  *  It will contain a IEE1905 structure
                                  *  when 'media_type' is one of the valid
                                  *  MEDIA_TYPE_IEEE_1901* values
                                  *  It will be empty in the rest of cases
                                  */
} i1905_media_type_entry_t;

typedef struct pushButtonEventNotificationTLV {
    uint8_t tlv_type;             /* Must always be set to TLV_TYPE_PUSH_BUTTON_EVENT_NOTIFICATION */

    uint8_t media_types_nr;       /* Number of media types included in this
                                  *  message: can be "0" or larger
                                  */

    i1905_media_type_entry_t *media_types;
} i1905_push_button_event_notification_tlv_t;

/*############################################################################
# Push button join notification TLV associated structures ("Section 6.4.20") #
#############################################################################*/
typedef struct pushButtonJoinNotificationTLV {
    uint8_t  tlv_type;            /* Must always be set to TLV_TYPE_PHSU_BUTTON_JOIN_NOTIFICATION */

    mac_addr al_mac_address;      /* 1905 AL MAC address of the device that sent
                                  *  the push button event notification message
                                  */

    uint16_t message_identifier;  /* The message identifier (MID) of the push
                                  *  button event notification message
                                  */

    mac_addr mac_address;         /* Interface specific MAC address of the
                                  *  interface of the transmitting device
                                  *  belonging to the medium on which a new
                                  *  device joined
                                  */

    mac_addr new_mac_address;     /* Interface specific MAC address of the
                                  *  interface of the new device that was joined
                                  *  to the network as a result of the push
                                  *  button configuration sequence
                                  */
} i1905_push_button_join_notification_tlv_t;

/*#############################################################################
# Generic PHY device information TLV associated structures ("Section 6.4.21") #
##############################################################################*/
typedef struct _genericPhyDeviceEntries {
    mac_addr  local_interface_address; /* MAC address of the local interface */

    i1905_generic_phy_common_data_t generic_phy_common_data;
                                       /* This structure contains the OUI,
                                       *  variant index and media specific
                                       * information of the local interface
                                       */

    uint8_t  variant_name[32];          /* Variant name UTF-8 string (NULL terminated */

    uint8_t  generic_phy_description_xml_url_len;
    char    *generic_phy_description_xml_url;
                                       /* URL to the "Generic Phy XML Description
                                       *  Document" of the variant. The string is
                                       *  'generic_phy_description_xml_url_len'
                                       *  bytes long including the final NULL character.
                                       */
} i1905_generic_phy_device_entry_t;

typedef struct genericPhyDeviceInformationTypeTLV {
    uint8_t  tlv_type;            /* Must always be set to TLV_TYPE_GENERIC_PHY_DEVICE_INFORMATION */

    mac_addr al_mac_address;      /* 1905 AL MAC address of the device */


    uint8_t                           local_interfaces_nr;
    i1905_generic_phy_device_entry_t *local_interfaces;
                                  /* List of local interfaces that are
                                  *  going to be reported as MEDIA_TYPE_UNKNOWN
                                  */
} i1905_generic_phy_device_information_tlv_t;

/*#########################################################################
# Device identification type TLV associated structures ("Section 6.4.22") #
##########################################################################*/
typedef struct deviceIdentificationTypeTLV {
    uint8_t tlv_type;               /* Must always be set to TLV_TYPE_DEVICE_IDENTIFICATION */

    char    friendly_name[64];      /* Friendly name UTF-8 string (NULL terminated) */

    char    manufacturer_name[64];  /* Manufacturer name UTF-8 string (NULL terminated) */

    char    manufacturer_model[64]; /* Manufacturer modem UTF-8 string (NULL terminated) */
} i1905_device_identification_tlv_t;

/*#######################################################################
# Control URL type TLV associated structures ("Section 6.4.23")         #
########################################################################*/
typedef struct controlUrlTypeTLV
{
    uint8_t  tlv_type;            /* Must always be set to TLV_TYPE_CONTROL_URL */

    char    *url;                 /* Pointer to a NULL terminated string
                                  *  containing the URL to a control or
                                  *  WebUI of the device
                                  */
} i1905_control_url_tlv_t;

/*#######################################################################
# IPv4 type TLV associated structures ("Section 6.4.24")                #
########################################################################*/
typedef struct _ipv4Entries {
    #define IPV4_TYPE_UNKNOWN (0)
    #define IPV4_TYPE_DHCP    (1)
    #define IPV4_TYPE_STATIC  (2)
    #define IPV4_TYPE_AUTOIP  (3)
    uint8_t type;                 /* One of the values from above */

    uint8_t ipv4_address[4];      /* IPv4 address associated to the interface */

    uint8_t ipv4_dhcp_server[4];  /* IPv4 address of the DHCP server (if
                                  *  known, otherwise set to all zeros)
                                  */
} i1905_ipv4_entry_t;

typedef struct _ipv4InterfaceEntries {
    mac_addr mac_address;         /* MAC address of the interface whose IPv4s
                                  *  are going to be reported.
                                  *
                                  *    NOTE: The standard says it can also
                                  *    be an AL MAC address instead of an
                                  *    interface MAC address.
                                  *    In that case I guess *all* IPv4s of
                                  *    the device (no matter the interface
                                  *    they are "binded" to) are reported.
                                  */

    uint8_t             ipv4_nr;
    i1905_ipv4_entry_t *ipv4;     /* List of IPv4s associated to this interface */
} i1905_ipv4_interface_entry_t;

typedef struct ipv4TypeTLV {
    uint8_t tlv_type;             /* Must always be set to TLV_TYPE_IPV4 */

    uint8_t                       ipv4_interfaces_nr;
    i1905_ipv4_interface_entry_t *ipv4_interfaces;
                                  /* List of interfaces with at least one IPv4 assigned */
} i1905_ipv4_tlv_t;

/*#######################################################################
# IPv6 type TLV associated structures ("Section 6.4.25")                #
########################################################################*/
typedef struct _ipv6Entries
{
    #define IPV6_TYPE_UNKNOWN (0)
    #define IPV6_TYPE_DHCP    (1)
    #define IPV6_TYPE_STATIC  (2)
    #define IPV6_TYPE_SLAAC   (3)
    uint8_t type;                    /* One of the values from above */

    uint8_t ipv6_address[16];        /* IPv6 address associated to the interface */

    uint8_t ipv6_address_origin[16]; /* If type == IPV6_TYPE_DHCP, this field
                                     *  contains the IPv6 address of the DHCPv6
                                     *  server.
                                     *  If type == IPV6_TYPE_SLAAC, this field
                                     *  contains the IPv6 address of the router
                                     *  that provided the SLAAC address.
                                     *  In any other case this field is set to
                                     *  all zeros.
                                     */
} i1905_ipv6_entry_t;

typedef struct _ipv6InterfaceEntries {
    mac_addr mac_address;         /* MAC address of the interface whose IPv4s
                                  *  are going to be reported.
                                  *
                                  *    NOTE: The standard says it can also
                                  *    be an AL MAC address instead of an
                                  *    interface MAC address.
                                  *    In that case I guess *all* IPv4s of
                                  *    the device (no matter the interface
                                  *    they are "binded" to) are reported.
                                  */

    uint8_t  ipv6_link_local_address[16];
                                  /* IPv6 link local address corresponding to this interface */

    uint8_t               ipv6_nr;
    i1905_ipv6_entry_t   *ipv6;   /* List of IPv4s associated to this interface */
} i1905_ipv6_interface_entry_t;

typedef struct ipv6TypeTLV {
    uint8_t tlv_type;             /* Must always be set to TLV_TYPE_IPV6 */

    uint8_t                       ipv6_interfaces_nr;
    i1905_ipv6_interface_entry_t *ipv6_interfaces;
                                  /* List of interfaces with at least one IPv6 assigned */
} i1905_ipv6_tlv_t;

/*#########################################################################################
# Push button generic PHY event notification TLV associated structures ("Section 6.4.26") #
###########################################################################################*/
typedef struct pushButtonGenericPhyEventNotificationTLV {
    uint8_t tlv_type;             /* Must always be set to TLV_TYPE_GENERIC_PHY_EVENT_NOTIFICATION */

    uint8_t                          local_interfaces_nr;
    i1905_generic_phy_common_data_t *local_interfaces;
                                  /* List of local interfaces of type
                                  *  MEDIA_TYPE_UNKNOWN for which a push button
                                  *  configuration method has been activated on
                                  *  the device that originates the push button
                                  *  event notification
                                  */
} i1905_generic_phy_event_notification_tlv_t;

/*#######################################################################
# Profile version TLV associated structures ("Section 6.4.27")          #
########################################################################*/
typedef struct x1905ProfileVersionTLV {
    uint8_t tlv_type;             /* Must always be set to TLV_TYPE_1905_PROFILE_VERSION */

    #define PROFILE_1905_1   (0x00)
    #define PROFILE_1905_1A  (0x01)
    uint8_t profile;              /* One of the values from above */
} i1905_profile_version_tlv_t;

/*#######################################################################
# Power off interface TLV associated structures ("Section 6.4.28")      #
########################################################################*/
typedef struct _powerOffInterfaceEntries {
    mac_addr interface_address;   /* MAC address of an interface in the "power off" state */

    uint16_t media_type;          /* Underlaying network technology
                                  *  One of the MEDIA_TYPE_* values
                                  */

    i1905_generic_phy_common_data_t generic_phy_common_data;
                                  /* If 'media_type' is MEDIA_TYPE_UNKNOWN,
                                  *  this structure contains the vendor OUI,
                                  *  variant index and media specific
                                  *  information of the interface
                                  *  Otherwise, it is set to all zeros
                                  */
} i1905_power_off_interface_entry_t;

typedef struct powerOffInterfaceTLV {
    uint8_t tlv_type;             /* Must always be set to TLV_TYPE_POWER_OFF_INTERFACE */

    uint8_t                           power_off_interfaces_nr;
    i1905_power_off_interface_entry_t *power_off_interfaces;
                                  /* List of local interfaces in the "power off" state */
} i1905_power_off_interface_tlv_t;

/*#################################################################################
# Interface power change information TLV associated structures ("Section 6.4.29") #
##################################################################################*/
typedef struct _powerChangeInformationEntries {
    mac_addr interface_address;     /* MAC address of an interface in the "power off" state */

    #define POWER_STATE_REQUEST_OFF  (0x00)
    #define POWER_STATE_REQUEST_ON   (0x01)
    #define POWER_STATE_REQUEST_SAVE (0x02)
    uint8_t  requested_power_state; /* One of the values from above */
} i1905_power_change_information_entry_t;

typedef struct interfacePowerChangeInformationTLV {
    uint8_t tlv_type;            /* Must always be set to TLV_TYPE_INTERFACE_POWER_CHANGE_INFORMATION */

    uint8_t                                 power_change_interfaces_nr;
    i1905_power_change_information_entry_t *power_change_interfaces;
                                 /* List of local interfaces for which a power
                                 *  status change is requested
                                 */
} i1905_interface_power_change_information_tlv_t;

/*############################################################################
# Interface power change status TLV associated structures ("Section 6.4.30") #
#############################################################################*/
typedef struct _powerChangeStatusEntries {
    mac_addr interface_address;  /* MAC address of an interface in the "power off" state */

    #define POWER_STATE_RESULT_COMPLETED          (0x00)
    #define POWER_STATE_RESULT_NO_CHANGE          (0x01)
    #define POWER_STATE_RESULT_ALTERNATIVE_CHANGE (0x02)
    uint8_t  result;             /* One of the values from above */
} i1905_power_change_status_entry_t;

typedef struct interfacePowerChangeStatusTLV {
    uint8_t tlv_type;            /* Must always be set to TLV_TYPE_INTERFACE_POWER_CHANGE_STATUS */

    uint8_t                            power_change_interfaces_nr;
    i1905_power_change_status_entry_t *power_change_interfaces;
                                 /* List of local interfaces whose power status
                                 *  change operation result is being reported
                                 */
} i1905_interface_power_change_status_tlv_t;

/*#######################################################################
# L2 neighbor device TLV associated structures ("Section 6.4.31")       #
########################################################################*/
typedef struct _l2NeighborsEntries {
    mac_addr  l2_neighbor_mac_address; /* MAC address of remote interface
                                       *  sharing the same L2 medium
                                       */

    uint16_t  behind_mac_addresses_nr;
    mac_addr (*behind_mac_addresses);  /* List of MAC addresses the remote
                                       *  device (owner of the remote
                                       *  interface) "knows" and that are
                                       *  not visible on this interface.
                                       *  TODO: Define better !!!
                                       */
} i1905_l2_neighbor_entry_t;

typedef struct _l2InterfacesEntries {
    mac_addr   local_mac_address; /* MAC address of the local interface whose
                                  *  L2 neighbors are going to be reported
                                  */

    uint16_t                   l2_neighbors_nr;
    i1905_l2_neighbor_entry_t *l2_neighbors;
                                  /* List of neighbors that share the same L2
                                  *  medium as the local interface
                                  */
} i1905_l2_interface_entry_t;

typedef struct l2NeighborDeviceTLV {
    uint8_t tlv_type;            /* Must always be set to TLV_TYPE_L2_NEIGHBOR_DEVICE */

    uint8_t                     local_interfaces_nr;
    i1905_l2_interface_entry_t *local_interfaces;
                                 /* List of interfaces with at least one IPv4 assigned */
} i1905_l2_neighbor_device_tlv_t;

/*#######################################################################
# Unknown TLV                                                           #
########################################################################*/
typedef struct unknownTLV {
    uint8_t   tlv_type;          /* Must always be set to TLV_TYPE_UNKOWN */
    uint8_t   real_tlv_type;     /* Original TLV type */
    uint16_t  v_nr;              /* Original TLV length */
    uint8_t  *v;                 /* Original TLV value */
} i1905_unknown_tlv_t;

/*#######################################################################
# TLV handlers and helper macros                                        #
########################################################################*/
typedef uint8_t* (*i1905_tlv_parse_cb_t)(uint8_t *tlv_value, uint16_t bytes_left);

typedef uint8_t* (*i1905_tlv_forge_cb_t)(void *memory_structure, uint16_t *len);

typedef void     (*i1905_tlv_free_cb_t)(void *memory_structure);

#define TLV_STRUCT_NAME_PREFIX_I1905 100
#define TLV_STRUCT_NAME_PREFIX_MAP   200

#if TLV_STRUCT_NAME_PREFIX == TLV_STRUCT_NAME_PREFIX_I1905
#define TLV_STRUCT_NAME(type) i1905_##type##_tlv_t
#elif TLV_STRUCT_NAME_PREFIX == TLV_STRUCT_NAME_PREFIX_MAP
#define TLV_STRUCT_NAME(type) map_##type##_tlv_t
#else
#define TLV_STRUCT_NAME(type) invalid
#endif


/* The TLV_FREE_FUNCTION macro creates two tlv free functions:
   - one with the correct type used in some macros below
   - one with void type to be used as tlv_free callback (and calls the first one)

   This is done to allow proper static code analysis of the
   free functions.  The tool cannot understand the generic
   free_1905_TLV_structure function which uses the void type functions.
*/
#define TLV_FREE_FUNCTION_NAME(type)      free_##type##_tlv
#define TLV_VOID_FREE_FUNCTION_NAME(type) free_##type##_tlv_void

#define TLV_FREE_FUNCTION(type)                                           \
static void TLV_FREE_FUNCTION_NAME(type)(TLV_STRUCT_NAME(type)*);         \
static void TLV_VOID_FREE_FUNCTION_NAME(type)(void *m)                    \
{                                                                         \
    TLV_FREE_FUNCTION_NAME(type)(m);                                      \
}                                                                         \
static void TLV_FREE_FUNCTION_NAME(type)(UNUSED TLV_STRUCT_NAME(type)* m)


#define PARSE_CHECK_EXP_LEN(exp_len) \
    if (len != (exp_len)) {          \
        return NULL;                 \
    }


#define PARSE_CHECK_MIN_LEN(min_len) \
    if (len < (min_len)) {           \
        return NULL;                 \
    }


#define PARSE_CHECK_INTEGRITY(type)                                                  \
    if (check_and_log_1905_TLV_malformed((p - packet_stream), len, ret->tlv_type)) { \
        TLV_FREE_FUNCTION_NAME(type)(ret);                                           \
        free(ret);                                                                   \
        return NULL;                                                                 \
    }


/* Check limit and free TLV using free function if needed
   !! can only be used from points where the
   tlv state is valid for the tlv free function
*/
#define PARSE_LIMIT_N_DROP(type, var, lim) \
    if (var > (lim)) {                     \
        TLV_FREE_FUNCTION_NAME(type)(ret); \
        free(ret);                         \
        return NULL;                       \
    }


#define PARSE_LIMIT(var, lim) \
    if (var > (lim)) {        \
        var = (lim);          \
    }


#define PARSE_CALLOC_RET                             \
    if (NULL == (ret = (calloc(1, sizeof(*ret))))) { \
        return NULL;                                 \
    }


/* Free TLV using free function and return NULL
   !! can only be called from points where the
   tlv state is valid for the tlv free function
*/
#define PARSE_FREE_RET_RETURN(type)    \
do {                                   \
    TLV_FREE_FUNCTION_NAME(type)(ret); \
    free(ret);                         \
    return NULL;                       \
} while(0);


#define PARSE_RETURN \
    return (uint8_t *)ret;


#define FORGE_MALLOC_RET                                         \
    if (NULL == (p = ret = malloc(TLV_HDR_SIZE + tlv_length))) { \
        return NULL;                                             \
    }


#define FORGE_RESERVE(p, n) \
do {                        \
    memset(p, 0, n);        \
    p += n;                 \
} while(0);


#define FORGE_RETURN                  \
    *len = TLV_HDR_SIZE + tlv_length; \
    return ret;

/*#######################################################################
# Main API functions                                                    #
########################################################################*/

/* This function receives a pointer to a stream of bytes representing a 1905
*  TLV according to "Section 6.4"
*
*  It then returns a pointer to a structure whose fields have already been
*  filled with the appropiate values extracted from the parsed stream.
*
*  The actual type of the returned pointer structure depends on the value of
*  the first byte pointed by "packet_stream" (ie. the "Type" field of the TLV):
*
*  If an error was encountered while parsing the stream, a NULL pointer is
*  returned instead.
*  Otherwise, the returned structure is dynamically allocated, and once it is
*  no longer needed, the user must call the "free_1905_TLV_structure()" function
*/
uint8_t *parse_1905_TLV_from_packet(uint8_t *packet_stream, uint16_t bytes_left);


/* This is the opposite of "parse_1905_TLV_from_packet()": it receives a
*  pointer to a TLV structure and then returns a pointer to a buffer which:
*    - is a packet representation of the TLV
*    - has a length equal to the value returned in the "len" output argument
*
*  "memory_structure" must point to a structure of one of the types returned by
*  "parse_1905_TLV_from_packet()"
*
*  If there is a problem this function returns NULL, otherwise the returned
*  buffer must be later freed by the caller (it is a regular, non-nested buffer,
*  so you just need to call "free()").
*
*  Note that the input structure is *not* freed. You still need to later call
*  "free_1905_TLV_structure()"
*/
uint8_t *forge_1905_TLV_from_structure(uint8_t *memory_structure, uint16_t *len);

/*#######################################################################
# Utility API functions                                                 #
########################################################################*/

/* This function receives a pointer to a TLV structure and then traverses it
*  and all nested structures, calling "free()" on each one of them
*
*  "memory_structure" must point to a structure of one of the types returned by
*  "parse_1905_TLV_from_packet()"
*/
void free_1905_TLV_structure(uint8_t *memory_structure);

/* Same as above but do not free memory_structure itself (e.g could be on stack) */
void free_1905_TLV_structure2(uint8_t *memory_structure);

/* 'forge_1905_TLV_from_structure()' returns a regular buffer which can be freed
*  using this macro defined to be free
*/
#define  free_1905_TLV_packet free

/* This function returns '0' if the two given pointers represent TLV structures
*  of the same type and they contain the same data
*
*  "memory_structure_1" and "memory_structure_2" must point (each) to a
*  structure of one of the types returned by "parse_1905_TLV_from_packet()"
*/
uint8_t compare_1905_TLV_structures(uint8_t *memory_structure_1, uint8_t *memory_structure_2);

/* The next function is used to call function "callback()" on each element of
*  the "memory_structure" structure
*
*  "memory_structure" must point to a structure of one of the types returned by
*  "parse_1905_TLV_from_packet()"
*
*  It takes four arguments:
*    - The structure whose elements are going to be visited
*    - A callback function that will be executed on each element with the
*      following arguments:
*       * A pointer to the "write()" function that will be used to dump text.
*         This is always the "write_function()" pointer provided as third
*         argument to the "visit_1905_TLV_structure()" function.
*       * The size of the element to print (1, 2, 4, n bytes)
*       * A prefix string.
*         This is always the "prefix" value provided as fourth argument to the
*         "visit_1905_TLV_structure()" function
*       * The name of the element (ex: "mac_address")
*       * A 'fmt' string which must be used to print the contents of the element
*       * A pointer to the element itself
*    - The "write()" function that will be used when the callback is executed
*    - A "prefix" string argument that will be used when the callback is
*      executed (it usually contains "context" information that the callback
*      function prints before anything else to make it easy to follow the
*      structure traversing order)
*/
void visit_1905_TLV_structure(uint8_t *memory_structure, void (*callback)(void (*write_function)(const char *fmt, ...),
                              const char *prefix, size_t size, const char *name, const char *fmt, void *p),
                              void (*write_function)(const char *fmt, ...), const char *prefix);

/* Use this function for debug purposes. It turns a TLV_TYPE_* variable into its
*  string representation.
*
*  Example: TLV_TYPE_AL_MAC_ADDRESS --> "TLV_TYPE_AL_MAC_ADDRESS"
*
*  Return "Unknown" if the provided type does not exist.
*/
char *convert_1905_TLV_type_to_string(uint8_t tlv_type);

int check_and_log_1905_TLV_malformed(int parsed, int len, uint8_t tlv_type);

/* Register a TLV handler */
void i1905_register_tlv(uint8_t type, char *name, i1905_tlv_parse_cb_t parse_cb,
                        i1905_tlv_forge_cb_t forge_cb, i1905_tlv_free_cb_t free_cb);

#define I1905_REGISTER_TLV(tlv, cb) i1905_register_tlv(tlv, #tlv, parse_##cb##_tlv, forge_##cb##_tlv, TLV_VOID_FREE_FUNCTION_NAME(cb))

#endif /* _1905_TLVS_H_ */
