/* packet-udx.c
 * Routines for udx dissection
 * Copyright 2024, jthomas.dev@protonmail.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LICENSE
 */

/*
 * (A short description of the protocol including links to specifications,
 *  detailed documentation, etc.)
 */

#include "config.h"
/* Define the name for the logging domain (try to avoid collisions with existing
 * domains) */
#define WS_LOG_DOMAIN "udx"

/* Global header providing a minimum base set of required macros and APIs */
#include <wireshark.h>

#if 0
/* "System" includes used only as needed */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
...
#endif

#include <epan/addr_resolv.h>
#include <epan/conversation.h>
#include <epan/epan_dissect.h>
#include <epan/expert.h> /* Include only as needed */
#include <epan/follow.h>
#include <epan/packet.h> /* Required dissection API header */
#include <epan/prefs.h>  /* Include only as needed */
#include <epan/proto_data.h>
#include <epan/to_str.h>
#include <wsutil/file_util.h>

#if 0
/* IF AND ONLY IF your protocol dissector exposes code to other dissectors
 * (which most dissectors don't need to do) then the 'public' prototypes and
 * data structures can go in the header file packet-udx.h. If not, then
 * a header file is not needed at all and this #include statement can be
 * removed. */
#include "packet-udx.h"
#endif

#define UDX_HEADER_DATA    0b00001
#define UDX_HEADER_END     0b00010
#define UDX_HEADER_SACK    0b00100
#define UDX_HEADER_MESSAGE 0b01000
#define UDX_HEADER_DESTROY 0b10000

#define UDX_PORT -1

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void
proto_reg_handoff_udx (void);
void
proto_register_udx (void);

// static int udx_tap;
static int udx_follow_tap;

/* Initialize the protocol and registered fields */
static int proto_udx;

static int hf_udx_magic_byte;
static int hf_udx_version;
static int hf_udx_flags;
static int hf_udx_flags_data;
static int hf_udx_flags_end;
static int hf_udx_flags_sack;
static int hf_udx_flags_message;
static int hf_udx_flags_destroy;
static int hf_udx_data_offset;
static int hf_udx_id;
static int hf_udx_window;
static int hf_udx_seq;
static int hf_udx_ack;
static int hf_udx_sack_start;
static int hf_udx_sack_end;
static int hf_udx_analysis;
static int hf_udx_analysis_flags;
static int hf_udx_analysis_duplicate_ack;
static int hf_udx_analysis_duplicate_ack_num;
static int hf_udx_analysis_duplicate_ack_frame;
static int hf_udx_analysis_acks_frame;
static int hf_udx_analysis_bytes_in_flight;
static int hf_udx_analysis_ack_rtt;
static int hf_udx_analysis_first_rtt;
static int hf_udx_analysis_rto;
static int hf_udx_analysis_rto_frame;
static int hf_udx_payload;
static int hf_udx_stream;
static int hf_udx_stream_pnum;
static int hf_udx_ts_relative;
static int hf_udx_ts_delta;

static expert_field ei_udx_analysis_retransmission;
static expert_field ei_udx_analysis_fast_retransmission;
static expert_field ei_udx_analysis_spurious_retransmission;
static expert_field ei_udx_analysis_lost_packet;
static expert_field ei_udx_analysis_ack_lost_packet;
static expert_field ei_udx_analysis_duplicate_ack;
static expert_field ei_udx_connection_end;
static expert_field ei_udx_connection_end_active;
static expert_field ei_udx_connection_end_passive;
static expert_field ei_udx_connection_destroy;
static expert_field ei_udx_mtu_mtuprobe;

static dissector_handle_t udx_handle;

/* Global sample preference ("controls" display of numbers) */
static bool udx_calculate_ts = true;
static bool udx_track_bytes_in_flight = true;
static bool udx_write_stream_dat_file = true; // todo, default false

static uint32_t udx_stream_count;

/* Initialize the subtree pointers */
static int ett_udx;
static int ett_udx_completeness;
static int ett_udx_flags;
static int ett_udx_sack;
static int ett_udx_analysis;
static int ett_udx_timestamps;

/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define UDX_MIN_LENGTH 20

static bool
test_udx_packet (tvbuff_t *tvb) {
    if (tvb_captured_length(tvb) < 20) {
        return false;
    }

    if (tvb_get_guint8(tvb, 0) != 0xff) {
        return false;
    }

    /* second byte version, we only understand version 1 */
    if (tvb_get_guint8(tvb, 1) != 0x01) {
        return false;
    }

    /* only the 5 lsb are used for flags in version 1 */
    guint8 flags = tvb_get_guint8(tvb, 2);
    if (flags & 0xE0) {
        return false;
    }

    /* if data_offset is set packet size must be at least header length +
     * data_offset */
    guint8 data_offset = tvb_get_guint8(tvb, 3);
    if (data_offset > 0 && tvb_captured_length(tvb) < (20u + data_offset)) {
        return false;
    }

    return true;
}

// udx header passed to tap listeners

// todo: move to packet-udx.h

typedef struct {
    uint32_t id;
    uint32_t window;
    uint32_t seq;
    uint32_t ack;
    uint8_t flags;
    uint8_t data_offset;
    uint32_t streamid;
    uint16_t sport;
    uint16_t dport;

    uint16_t payload_len;

#define UDX_MAX_SACK_RANGES 32
    address ip_src;
    address ip_dst;

    uint8_t nsacks;

    // stream id (ge)
    uint32_t stream;

    uint32_t sack_left_edge[UDX_MAX_SACK_RANGES];
    uint32_t sack_right_edge[UDX_MAX_SACK_RANGES];

} udx_packet_t;

typedef struct udx_stream_s udx_stream_t;

#define UDX_A_RETRANSMISSION          0x01
#define UDX_A_LOST_PACKET             0x02
#define UDX_A_ACK_LOST_PACKET         0x04
#define UDX_A_DUPLICATE_ACK           0x08
#define UDX_A_FAST_RETRANSMISSION     0x10
#define UDX_A_SPURIOUS_RETRANSMISSION 0x20

typedef struct {
    uint32_t frame_acked;
    nstime_t ts;

    uint32_t retransmit_frame;
    nstime_t retransmit_ts;

    uint16_t flags; // UDX_A_*

    uint32_t dupack_num;
    uint32_t dupack_frame;
    uint32_t bytes_in_flight;

} udx_acked_t;

typedef struct udx_unacked_s udx_unacked_t;

struct udx_unacked_s {
    struct udx_unacked_s *next;
    guint32 frame;
    guint32 seq;
    uint16_t payload_len; /* todo: count bytes in flight on the stream and remove
                             this */
    nstime_t ts;
};

typedef struct {
    uint32_t seq; // highest seen seq. nextseq = seq+1
    uint32_t ack; // seqinfo->lastack in tcp
    uint32_t flags;
    uint32_t remote_id;
    uint32_t window;

    bool id_wildcard; // true if return flow has not been seen

    // in tcp this is under the optional 'tcp_analyze_seq_info' pointer,
    // for us it's not optional so put it directly in the flow_t struct

    udx_unacked_t
        *unacked_packets; /* List of packets for which we haven't seen an ACK */

    uint16_t packet_count;           /* How many unacked packets we're currently storing */
    nstime_t lastacktime;            /* Time of the last ack packet */
    uint32_t lastnondupack;          /* frame number of last seen non dupack */
    uint32_t dupacknum;              /* dupack number */
    uint32_t highest_contiguous_seq; // for identifying when an ack is for a an
                                     // unseen seq
    uint32_t high_seq_frame;         // frame with highest seq sent
    nstime_t high_seq_time;          /* Time of the nextseq packet so we can
                                      * distinguish between retransmission,
                                      * fast retransmissions and outoforder
                                      */
    uint16_t flow_count;             // number of flows in this direction
    bool valid_bif;

    bool is_closing_initiator;

    uint32_t last_packet_flags; // UDX_A_*

    // copied from packet_t
    uint8_t num_sack_ranges;
    uint32_t sack_left_edge[UDX_MAX_SACK_RANGES];
    uint32_t sack_right_edge[UDX_MAX_SACK_RANGES];
} udx_flow_t;

struct udx_stream_s {
    uint32_t stream;
    uint32_t pnum; // packet number within udx stream

    udx_flow_t flow1;
    udx_flow_t flow2;

    udx_flow_t *fwd;
    udx_flow_t *rev;

    udx_acked_t *acked_info; // cache interesting acked struct
    wmem_tree_t *acked_table;

    nstime_t ts_first;
    nstime_t ts_first_rtt;
    nstime_t ts_prev;

    uint8_t flow_direction;
    uint8_t conversation_completeness; // todo

    udx_stream_t *prev;

    FILE *file; // for stream data
};

static udx_stream_t *
get_stream (packet_info *pinfo, udx_packet_t *pkt) {
    conversation_t *conv;

    uint32_t remote_id = pkt->id;

    int direction = cmp_address(&pinfo->src, &pinfo->dst);
    if (direction == 0) {
        direction = (pinfo->srcport > pinfo->destport) ? 1 : -1;
    }

    // we know the remote id, but not necessarily our own id
    // first check for wildcard conversation in our direction

    conv =
        find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, CONVERSATION_UDX, pinfo->srcport, pinfo->destport, 0);

    if (!conv) {
        conv =
            conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, CONVERSATION_UDX, pinfo->srcport, pinfo->destport, 0);
    }

    udx_stream_t *stream =
        (udx_stream_t *) conversation_get_proto_data(conv, proto_udx);
    udx_stream_t *head = stream;

    udx_stream_t *wildcard = NULL;

    while (stream) {
        if (stream->flow1.remote_id == remote_id ||
            stream->flow2.remote_id == remote_id) {
            break;
        }
        if (stream->flow1.id_wildcard || stream->flow2.id_wildcard) {
            wildcard = stream;
        }
        stream = stream->prev;
    }

    if (!stream && wildcard) {
        stream = wildcard;
        ws_info("matching stream to wildcard stream %u", stream->stream);
    }

    bool new_stream = false;

    if (!stream) {
        ws_info("creating stream stream=%u remote_id=%u", udx_stream_count, remote_id);

        stream = wmem_new0(wmem_file_scope(), udx_stream_t);
        stream->acked_table = wmem_tree_new(wmem_file_scope());

        stream->ts_first.secs = pinfo->abs_ts.secs;
        stream->ts_first.nsecs = pinfo->abs_ts.nsecs;

        stream->ts_prev.secs = pinfo->abs_ts.secs;
        stream->ts_prev.nsecs = pinfo->abs_ts.nsecs;

        nstime_set_zero(&stream->ts_first_rtt);

        stream->flow_direction = direction;
        stream->conversation_completeness = 0;
        stream->stream = udx_stream_count++;

        stream->flow1.valid_bif = true;
        stream->flow2.valid_bif = true;

        if (head) {
            stream->prev = head;
        }
        conversation_add_proto_data(conv, proto_udx, stream);
        new_stream = true;

        if (udx_write_stream_dat_file) {
            char filename[2048];
            snprintf(filename, 2048, "/tmp/stream-%u.dat", stream->stream);
            stream->file = ws_fopen(filename, "w");
        }
    }

    if (direction >= 0) {
        stream->fwd = &stream->flow1;
        stream->rev = &stream->flow2;
    } else {
        stream->fwd = &stream->flow2;
        stream->rev = &stream->flow1;
    }

    stream->fwd->remote_id = remote_id;

    if (new_stream) {
        stream->rev->id_wildcard = true;
    }

    stream->acked_info = NULL;

    return stream;
}

typedef struct {
    nstime_t delta_ts;
    uint32_t pnum;
    uint8_t udx_snd_manual_analysis;
    uint32_t stream;
} udx_per_packet_data_t;

static void
udx_calculate_timestamps (packet_info *pinfo, udx_stream_t *stream, udx_per_packet_data_t *udxppd) {

    if (!stream) {
        return;
    }

    udxppd->pnum = ++stream->pnum;
    nstime_delta(&udxppd->delta_ts, &pinfo->abs_ts, &stream->ts_prev);

    stream->ts_prev.secs = pinfo->abs_ts.secs;
    stream->ts_prev.nsecs = pinfo->abs_ts.nsecs;
}

static inline bool
gt_seq (uint32_t s1, uint32_t s2) {
    return (int32_t) (s2 - s1) < 0;
}

static inline bool
lt_seq (uint32_t s1, uint32_t s2) {
    return (int32_t) (s1 - s2) < 0;
}

static inline bool
ge_seq (uint32_t s1, uint32_t s2) {
    return (int32_t) (s2 - s1) <= 0;
}
static inline bool
le_seq (uint32_t s1, uint32_t s2) {
    return (int32_t) (s1 - s2) <= 0;
}

static void
udx_analyze_get_acked_info (uint32_t frame, uint32_t seq, uint32_t ack, bool createflag, udx_stream_t *stream) {
    wmem_tree_key_t key[4];

    key[0].length = 1;
    key[0].key = &frame;

    key[1].length = 1;
    key[1].key = &seq;

    key[2].length = 1;
    key[2].key = &ack;

    key[3].length = 0;
    key[3].key = NULL;

    if (!stream) {
        return;
    }

    stream->acked_info =
        (udx_acked_t *) wmem_tree_lookup32_array(stream->acked_table, key);
    if ((!stream->acked_info) && createflag) {
        stream->acked_info = wmem_new0(wmem_file_scope(), udx_acked_t);
        wmem_tree_insert32_array(stream->acked_table, key, (void *) stream->acked_info);
    }
}

// some code that uses pkt->flags & UDX_HEADER_DATA should use it instad
static void
udx_analyze_sequence_number (packet_info *pinfo, uint32_t seq, uint32_t ack, uint16_t payload_len, uint16_t flags, uint32_t window, udx_stream_t *stream) {

    udx_unacked_t *unacked = NULL;

    if (!stream) {
        return;
    }

#if 0
    ws_info("frame=%u seq=%u ack=%u", pinfo->num, seq, ack);
    ws_info("  fwd flags=%x04x nextseq=%u ack=%u unacked_count=%u", stream->fwd->last_packet_flags, stream->fwd->seq+1, stream->rev->ack, stream->fwd->packet_count);

    for(unacked = stream->fwd->unacked_packets; unacked; unacked = unacked->next) {
        ws_info("    frame=%u seq=%u", unacked->frame, unacked->seq);
    }

    ws_info("  rev flags=%x04x nextseq=%u ack=%u unacked_count=%u", stream->rev->last_packet_flags, stream->rev->seq+1, stream->fwd->ack, stream->rev->packet_count);

    for(unacked = stream->rev->unacked_packets; unacked; unacked = unacked->next) {
        ws_info("    frame=%u seq=%u", unacked->frame, unacked->seq);
    }

#endif
    if (flags & UDX_HEADER_SACK) {
        // tag packet here? sack replaces reno tcp's duplicate ack for 99% of cases
    }

    if (window && window == stream->fwd->window && seq == stream->fwd->seq + 1 &&
        ack == stream->fwd->ack &&
        (flags & (UDX_HEADER_DATA | UDX_HEADER_DESTROY | UDX_HEADER_END |
                  UDX_HEADER_MESSAGE)) == 0) {
        ws_info("duplicate ack: pinfo->num=%u, seq=%u, ack=%u stream->fwd->seq=%u "
                "stream->fwd->ack=%u",
                pinfo->num,
                seq,
                ack,
                stream->fwd->seq,
                stream->fwd->ack);
        stream->fwd->dupacknum++;
        if (!stream->acked_info) {
            udx_analyze_get_acked_info(pinfo->num, seq, ack, true, stream);
        }

        stream->acked_info->flags |= UDX_A_DUPLICATE_ACK;
        stream->acked_info->dupack_num = stream->fwd->dupacknum;
        stream->acked_info->dupack_frame = stream->fwd->lastnondupack;
    }

    /* LOST PACKET
     * if the packet is beyond the last seen nextseq we missed some previous
     * segment note this is wireshark that missed the segment most likely
     */

    if (stream->fwd->seq && gt_seq(seq, stream->fwd->seq + 1)) {
        if (!stream->acked_info) {
            udx_analyze_get_acked_info(pinfo->num, seq, ack, true, stream);
        }
        stream->acked_info->flags |= UDX_A_LOST_PACKET;
        stream->fwd->valid_bif = false;
    }

    /* WINDOW UPDATE */
    // todo

    /* WINDOW FULL */
    // todo

    // finished_fwd:

    // new ack, reset dupack counters
    if (ack != stream->fwd->ack) {
        stream->fwd->lastnondupack = pinfo->num;
        stream->fwd->dupacknum = 0;
    }

    /* ACKED LOST PACKET  */
    if (stream->rev->highest_contiguous_seq &&
        gt_seq(ack, stream->rev->highest_contiguous_seq)) {
        ws_info("todo: acked lost packet");
    }

    /* RETRANSMISSION / FAST RETRANSMISSION / OUT OF ORDER
     * has data and does not advace the sequence number
     */

    if (flags & UDX_HEADER_DATA) {
        bool seq_not_advanced = stream->fwd->seq && le_seq(seq, stream->fwd->seq);

        // check for spurious retransmission
        if (lt_seq(seq, stream->rev->ack)) {
            if (!stream->acked_info) {
                udx_analyze_get_acked_info(pinfo->num, seq, ack, true, stream);
            }
            stream->acked_info->flags |= UDX_A_SPURIOUS_RETRANSMISSION;
            ws_info("spurious rtx seq=%u stream->rev->ack=%u\n", seq, stream->rev->ack);
            goto finished_checking_retransmission_type;
        }
        // todo: check for fast retransmission or out-of-order
        // see tcp_analyze_sequence_number from packet-tcp.c

        // for now use one retransmission type for everything

        if (seq_not_advanced) {
            if (!stream->acked_info) {
                udx_analyze_get_acked_info(pinfo->num, seq, ack, true, stream);
            }

            uint64_t t =
                (pinfo->abs_ts.secs - stream->rev->lastacktime.secs) * 1000000000 +
                (pinfo->abs_ts.nsecs) - stream->rev->lastacktime.nsecs;

            if (t < 20000000 && stream->rev->num_sack_ranges > 0) {
                if (!stream->acked_info) {
                    udx_analyze_get_acked_info(pinfo->num, seq, ack, true, stream);
                }

                bool sacked = false;
                for (int i = 0; i < stream->rev->num_sack_ranges && !sacked; i++) {
                    sacked = (seq >= stream->rev->sack_left_edge[i] && seq <= stream->rev->sack_right_edge[i]);
                }
                if (!sacked) {
                    if (!stream->acked_info) {
                        udx_analyze_get_acked_info(pinfo->num, seq, ack, true, stream);
                    }
                    stream->acked_info->flags |= UDX_A_FAST_RETRANSMISSION;
                    goto finished_checking_retransmission_type;
                }
            }

            stream->acked_info->flags |= UDX_A_RETRANSMISSION;

            // fallback - use this packet for retransmission time
            // nextseqtime / nextseqframe in TCP

            nstime_delta(&stream->acked_info->retransmit_ts, &pinfo->abs_ts, &stream->fwd->high_seq_time);
            stream->acked_info->retransmit_frame = stream->fwd->high_seq_frame;

            // best case - we have the exact packet in the list of unacked packets
            // (might not if we ran low on memory)
            udx_unacked_t *u = stream->fwd->unacked_packets;

            while (u) {
                if (ge_seq(u->seq, seq)) {
                    nstime_delta(&stream->acked_info->retransmit_ts, &pinfo->abs_ts, &u->ts);
                    stream->acked_info->retransmit_frame = u->frame;
                }
                u = u->next;
            }
        }
    }

finished_checking_retransmission_type:

    if (flags & UDX_HEADER_DATA /*&& stream->fwd->packet_count < UDX_MAX_UNACKED_SEGMENTS*/) {
        udx_unacked_t *ua = wmem_new(wmem_file_scope(), udx_unacked_t);
        ua->next = stream->fwd->unacked_packets;
        stream->fwd->unacked_packets = ua;
        stream->fwd->packet_count++;
        ua->frame = pinfo->num;
        ua->seq = seq;
        ua->ts = pinfo->abs_ts;
        ua->payload_len = payload_len;
    }

    // store highest number seen so far for nextseq

    if (gt_seq(seq, stream->fwd->seq)) {
        // todo: if we do window probes, exempt this code
        stream->fwd->seq = seq;
        stream->fwd->high_seq_frame = pinfo->num;
        stream->fwd->high_seq_time.secs = pinfo->abs_ts.secs;
        stream->fwd->high_seq_time.nsecs = pinfo->abs_ts.nsecs;

        if (seq == stream->fwd->seq + 1) {
            stream->fwd->highest_contiguous_seq = seq;
        }

        if ((!stream->acked_info) ||
            !(stream->acked_info->flags & UDX_A_RETRANSMISSION ||
              stream->acked_info->flags & UDX_A_SPURIOUS_RETRANSMISSION)) {

            if (flags & UDX_HEADER_DATA) {
                int direction = cmp_address(&pinfo->src, &pinfo->dst);

                if (direction == 0) {
                    direction = (pinfo->srcport > pinfo->destport) ? 1 : -1;
                }

                if (direction != stream->flow_direction) {
                    stream->flow_direction = direction;
                    stream->fwd->flow_count++;
                } else {
                    if (stream->fwd->flow_count == 0) {
                        stream->fwd->flow_count++;
                    }
                }
            }
        }
    }

    stream->fwd->window = window;
    stream->fwd->ack = ack;
    stream->fwd->lastacktime.secs = pinfo->abs_ts.secs;
    stream->fwd->lastacktime.nsecs = pinfo->abs_ts.nsecs;

    /* remove all segments this ACK's and free them */

    udx_unacked_t *prev = NULL;
    unacked = stream->rev->unacked_packets;

    while (unacked) {

        // precise match
        if (ack == unacked->seq + 1) {
            udx_analyze_get_acked_info(pinfo->num, seq, ack, true, stream);
            // ws_info("frame=%u ack=%u rev->unacked->seq=%u unacked->frame=%u",
            // pinfo->num, ack, unacked->seq + 1, unacked->frame);
            stream->acked_info->frame_acked = unacked->frame;
            nstime_delta(&stream->acked_info->ts, &pinfo->abs_ts, &unacked->ts);
        } else if (ge_seq(unacked->seq, ack)) {
            // acknowledges a segment prior to this one, leave it alone and move to
            // the next
            prev = unacked;
            unacked = unacked->next;
            continue;
        }

        udx_unacked_t *tmp = unacked->next;

        if (!prev) {
            stream->rev->unacked_packets = tmp;
        } else {
            prev->next = tmp;
        }
        wmem_free(wmem_file_scope(), unacked);
        unacked = tmp;

        stream->rev->packet_count--;
    }

    /* bytes in flight tracking */

    uint32_t in_flight = 0;
    uint32_t delivered = 0;

    unacked = stream->fwd->unacked_packets;

    if (payload_len > 0 && unacked /*&& stream->fwd->valid_bif */) {

        while (unacked) {
            in_flight += unacked->payload_len;
            unacked = unacked->next;
        }

        for (int i = 0; i < stream->rev->num_sack_ranges; i++) {
            delivered +=
                stream->rev->sack_right_edge[i] - stream->rev->sack_left_edge[i];
        }

        in_flight -= delivered;

        if (in_flight > 0 && in_flight < 2000000000) {
            if (!stream->acked_info) {
                udx_analyze_get_acked_info(pinfo->num, seq, ack, true, stream);
            }
            stream->acked_info->bytes_in_flight = in_flight;
        }
    }
}
static void
udx_print_retransmission (packet_info *pinfo, tvbuff_t *tvb, proto_tree *flags_tree, proto_item *flags_item, udx_acked_t *ta) {
    if (ta->flags & UDX_A_RETRANSMISSION) {
        expert_add_info(pinfo, flags_item, &ei_udx_analysis_retransmission);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[UDX Retransmission] ");

        if (ta->retransmit_ts.secs || ta->retransmit_ts.nsecs) {
            flags_item = proto_tree_add_time(flags_tree, hf_udx_analysis_rto, tvb, 0, 0, &ta->retransmit_ts);
            proto_item_set_generated(flags_item);
            flags_item = proto_tree_add_uint(flags_tree, hf_udx_analysis_rto_frame, tvb, 0, 0, ta->retransmit_frame);
            proto_item_set_generated(flags_item);
        }
    }

    if (ta->flags & UDX_A_FAST_RETRANSMISSION) {
        expert_add_info(pinfo, flags_item, &ei_udx_analysis_retransmission);
        expert_add_info(pinfo, flags_item, &ei_udx_analysis_fast_retransmission);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[UDX Fast Retransmission] ");
        if (ta->retransmit_ts.secs || ta->retransmit_ts.nsecs) {
            flags_item = proto_tree_add_time(flags_tree, hf_udx_analysis_rto, tvb, 0, 0, &ta->retransmit_ts);
            proto_item_set_generated(flags_item);
            flags_item = proto_tree_add_uint(flags_tree, hf_udx_analysis_rto_frame, tvb, 0, 0, ta->retransmit_frame);
            proto_item_set_generated(flags_item);
        }
    }

    if (ta->flags & UDX_A_SPURIOUS_RETRANSMISSION) {
        expert_add_info(pinfo, flags_item, &ei_udx_analysis_retransmission);
    }
}
static void
udx_print_lost (packet_info *pinfo, proto_item *flags_item, udx_acked_t *ta) {
    if (ta->flags & UDX_A_LOST_PACKET) {
        expert_add_info(pinfo, flags_item, &ei_udx_analysis_lost_packet);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[UDX Previous segment not captured] ");
    }
    if (ta->flags & UDX_A_ACK_LOST_PACKET) {
        expert_add_info(pinfo, flags_item, &ei_udx_analysis_ack_lost_packet);
        col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[UDX ACKed unseen packet] ");
    }
}
static void
udx_print_duplicate_acks (packet_info *pinfo, tvbuff_t *tvb, proto_tree *flags_tree, udx_acked_t *ta, proto_tree *tree) {
    proto_item *flags_item;

    if (ta->dupack_num) {
        if (ta->flags & UDX_A_DUPLICATE_ACK) {
            flags_item =
                proto_tree_add_none_format(flags_tree, hf_udx_analysis_duplicate_ack, tvb, 0, 0, "This is a UDX duplicate ack");

            proto_item_set_generated(flags_item);
            col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[UDX Dup ACK %u#%u] ", ta->dupack_frame, ta->dupack_num);
        }

        flags_item = proto_tree_add_uint(tree, hf_udx_analysis_duplicate_ack_num, tvb, 0, 0, ta->dupack_num);
        proto_item_set_generated(flags_item);

        flags_item = proto_tree_add_uint(tree, hf_udx_analysis_duplicate_ack_frame, tvb, 0, 0, ta->dupack_frame);
        proto_item_set_generated(flags_item);

        expert_add_info_format(pinfo, flags_item, &ei_udx_analysis_duplicate_ack, "Duplicate ACK %u", ta->dupack_num);
    }
}

static void
udx_print_bytes_in_flight (packet_info *pinfo _U_, tvbuff_t *tvb, proto_tree *flags_tree, udx_acked_t *ta) {
    if (udx_track_bytes_in_flight) {
        proto_item *flags_item =
            proto_tree_add_uint(flags_tree, hf_udx_analysis_bytes_in_flight, tvb, 0, 0, ta->bytes_in_flight);
        proto_item_set_generated(flags_item);
    }
}

static void
udx_print_sequence_number_analysis (packet_info *pinfo, tvbuff_t *tvb, proto_tree *parent_tree, udx_stream_t *stream, uint32_t seq, uint32_t ack) {
    udx_acked_t *ta = NULL;
    proto_item *item = NULL;
    proto_item *tree = NULL;

    proto_tree *flags_tree = NULL;

    if (!stream) {
        return;
    }

    if (!stream->acked_info) {
        udx_analyze_get_acked_info(pinfo->num, seq, ack, false, stream);
    }
    ta = stream->acked_info;

    if (!ta) {
        return;
    }

    item = proto_tree_add_item(parent_tree, hf_udx_analysis, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(item);

    tree = proto_item_add_subtree(item, ett_udx_analysis);

    if (ta->frame_acked) {
        item = proto_tree_add_uint(tree, hf_udx_analysis_acks_frame, tvb, 0, 0, ta->frame_acked);
        proto_item_set_generated(item);
        if (ta->ts.secs || ta->ts.nsecs) {
            item = proto_tree_add_time(tree, hf_udx_analysis_ack_rtt, tvb, 0, 0, &ta->ts);
            proto_item_set_generated(item);
        }
    }

    if (!nstime_is_zero(&stream->ts_first_rtt)) {
        item = proto_tree_add_time(tree, hf_udx_analysis_first_rtt, tvb, 0, 0, &stream->ts_first_rtt);
        proto_item_set_generated(item);
    }

    if (ta->bytes_in_flight) {
        udx_print_bytes_in_flight(pinfo, tvb, tree, ta);
    }

    if (ta->flags) {
        item = proto_tree_add_item(tree, hf_udx_analysis_flags, tvb, 0, 0, ENC_NA);
        proto_item_set_generated(item);
        flags_tree = proto_item_add_subtree(item, ett_udx_analysis);

        udx_print_retransmission(pinfo, tvb, flags_tree, item, ta);
        udx_print_lost(pinfo, item, ta);
        udx_print_duplicate_acks(pinfo, tvb, flags_tree, ta, tree);
    }
}

static char *
udx_flags_to_string (wmem_allocator_t *scope, const udx_packet_t *pkt) {
    static char *flags[] = {"DATA", "END", "SACK", "MESSAGE", "DESTROY"};

    char *buf = wmem_alloc(scope, 64);
    buf[0] = '\0';

    char *p = buf;

    p = g_stpcpy(p, "ACK");

    for (int i = 0; i < 5; i++) {
        if (pkt->flags & (1 << i)) {
            p = g_stpcpy(p, ", ");
            p = g_stpcpy(p, flags[i]);
        }
    }

    return buf;
}

static void
udx_print_timestamps (packet_info *pinfo, tvbuff_t *tvb, proto_tree *parent_tree, udx_stream_t *stream, udx_per_packet_data_t *udxppd) {
    proto_item *item;
    proto_tree *tree;
    nstime_t ts;

    if (!stream) {
        return;
    }
    tree = proto_tree_add_subtree(parent_tree, tvb, 0, 0, ett_udx_timestamps, &item, "Timestamps");
    proto_item_set_generated(item);

    nstime_delta(&ts, &pinfo->abs_ts, &stream->ts_first);

    item = proto_tree_add_time(tree, hf_udx_ts_relative, tvb, 0, 0, &ts);
    proto_item_set_generated(item);

    if (!udxppd) {
        udxppd = (udx_per_packet_data_t *) p_get_proto_data(
            wmem_file_scope(), pinfo, proto_udx, 0
        );
    }

    if (udxppd) {
        item = proto_tree_add_time(tree, hf_udx_ts_delta, tvb, 0, 0, &udxppd->delta_ts);
        proto_item_set_generated(item);
    }
}

/* Code to actually dissect the packets */
static int
dissect_udx (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {

    proto_tree *udx_tree = NULL;
    proto_item *data_item = NULL;
    proto_item *tf_end = NULL;
    proto_item *tf_destroy = NULL;

    if (!test_udx_packet(tvb)) {
        return 0;
    }

    udx_packet_t *pkt = wmem_new0(pinfo->pool, udx_packet_t);

    // just fill in 'protocol' and 'info' columns
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDX");
    col_clear(pinfo->cinfo, COL_INFO);

    // parsing packet info

    pkt->flags = tvb_get_guint8(tvb, 2);
    pkt->data_offset = tvb_get_guint8(tvb, 3);

    pkt->sport = pinfo->srcport;
    pkt->dport = pinfo->destport;

    pkt->id = tvb_get_guint32(tvb, 4, ENC_LITTLE_ENDIAN);
    pkt->window = tvb_get_guint32(tvb, 8, ENC_LITTLE_ENDIAN);
    pkt->seq = tvb_get_guint32(tvb, 12, ENC_LITTLE_ENDIAN);
    pkt->ack = tvb_get_guint32(tvb, 16, ENC_LITTLE_ENDIAN);

    copy_address_shallow(&pkt->ip_src, &pinfo->src);
    copy_address_shallow(&pkt->ip_dst, &pinfo->dst);

    uint32_t offset = 20;

    if (pkt->flags & UDX_HEADER_SACK) {
        unsigned int header_end =
            pkt->data_offset ? 20u + pkt->data_offset : tvb_captured_length(tvb);
        while (offset + 8 <= header_end) {
            uint32_t sack_start = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
            uint32_t sack_end = tvb_get_guint32(tvb, offset + 4, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "%u:%u ", sack_start, sack_end);

            pkt->sack_left_edge[pkt->nsacks] = sack_start;
            pkt->sack_right_edge[pkt->nsacks] = sack_end;

            offset += 8;
            pkt->nsacks++;
        }
    }
    char *flags_str = udx_flags_to_string(pinfo->pool, pkt);

    if (tree) {
        proto_item *ti = proto_tree_add_item(tree, proto_udx, tvb, 0, -1, ENC_NA);
        udx_tree = proto_item_add_subtree(ti, ett_udx);

        proto_tree_add_item(udx_tree, hf_udx_magic_byte, tvb, 0, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(udx_tree, hf_udx_version, tvb, 1, 1, ENC_LITTLE_ENDIAN);

        proto_item *pi = proto_tree_add_uint_format(
            udx_tree, hf_udx_flags, tvb, 2, 1, pkt->flags, "Flags: 0x%02x (%s)", pkt->flags, flags_str
        );

        proto_tree *field_tree = proto_item_add_subtree(pi, ett_udx_flags);

        proto_tree_add_boolean(field_tree, hf_udx_flags_data, tvb, 2, 1, pkt->flags);
        tf_end = proto_tree_add_boolean(field_tree, hf_udx_flags_end, tvb, 2, 1, pkt->flags);
        proto_tree_add_boolean(field_tree, hf_udx_flags_sack, tvb, 2, 1, pkt->flags);
        proto_tree_add_boolean(field_tree, hf_udx_flags_message, tvb, 2, 1, pkt->flags);
        tf_destroy = proto_tree_add_boolean(field_tree, hf_udx_flags_destroy, tvb, 2, 1, pkt->flags);

        data_item = proto_tree_add_item(udx_tree, hf_udx_data_offset, tvb, 3, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(udx_tree, hf_udx_id, tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(udx_tree, hf_udx_window, tvb, 8, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(udx_tree, hf_udx_seq, tvb, 12, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(udx_tree, hf_udx_ack, tvb, 16, 4, ENC_LITTLE_ENDIAN);

        if (pkt->flags & UDX_HEADER_SACK) {
            unsigned int header_end =
                pkt->data_offset ? 20u + pkt->data_offset : tvb_captured_length(tvb);
            while (offset + 8 <= header_end) {
                proto_tree_add_item(udx_tree, hf_udx_sack_start, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(udx_tree, hf_udx_sack_end, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
            }
        }
    }

    col_add_fstr(pinfo->cinfo, COL_INFO, "%u -> %u id=%u seq=%u ack=%u ", pkt->sport, pkt->dport, pkt->id, pkt->seq, pkt->ack);

    col_append_str(pinfo->cinfo, COL_INFO, "ACK");

    if (pkt->flags & UDX_HEADER_DATA)
        col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "DATA");
    if (pkt->flags & UDX_HEADER_END)
        col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "END");
    if (pkt->flags & UDX_HEADER_SACK) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "SACK");
        for (int i = 0; i < pkt->nsacks; i++) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "%u-%u", pkt->sack_left_edge[i], pkt->sack_right_edge[i]);
        }
    }
    if (pkt->flags & UDX_HEADER_MESSAGE)
        col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "MSG");
    if (pkt->flags & UDX_HEADER_DESTROY)
        col_append_sep_str(pinfo->cinfo, COL_INFO, ",", "DESTROY");

    if (tvb_captured_length(tvb) > offset) {
        proto_tree_add_item(udx_tree, hf_udx_payload, tvb, offset, -1, ENC_NA);
    }

    if (pkt->flags & UDX_HEADER_SACK) {
    }

    udx_stream_t *stream = get_stream(pinfo, pkt);

    if (stream && (pkt->flags & UDX_HEADER_DATA) && pkt->seq == 0) {
        ws_info("first data packet for stream %u in direction %u", stream->stream, stream->flow_direction);
    }

    udx_per_packet_data_t *udxppd = p_get_proto_data(wmem_file_scope(), pinfo, proto_udx, 0);

    if (!udxppd) {
        udxppd = wmem_new(wmem_file_scope(), udx_per_packet_data_t);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_udx, 0, udxppd);
    }

    if (udx_calculate_ts) {

        if (!pinfo->fd->visited) {
            udx_calculate_timestamps(pinfo, stream, udxppd);
        }
    }

    if (stream) {
        if (udx_tree) {
            proto_item_set_generated(proto_tree_add_uint(udx_tree, hf_udx_stream, tvb, offset, 0, stream->stream));
            if (udxppd) {
                proto_item_set_generated(proto_tree_add_uint(
                    udx_tree, hf_udx_stream_pnum, tvb, offset, 0, udxppd->pnum
                ));
            }
        }

        pkt->stream = stream->stream;
        udxppd->stream = stream->stream;

        // for UI conversation callbacks
        pinfo->stream_id = stream->stream;
        stream->fwd->num_sack_ranges = pkt->nsacks;
    }

    // skip manual analysis

    // skip relative sequence numbers - we start at zero anyways
    uint32_t reported_len = tvb_reported_length(tvb);
    if (reported_len < 20) {
        // todo: error on packet
        pkt->payload_len = 0;
    } else {
        pkt->payload_len = reported_len - 20;
    }

    if (!pinfo->fd->visited) {
        udx_analyze_sequence_number(pinfo, pkt->seq, pkt->ack, pkt->payload_len, pkt->flags, pkt->window, stream);
    }

    /* If this protocol has a sub-dissector call it here, see section 1.8 of
     * README.dissector for more information. */

    // create and add expert item

    if (pkt->data_offset && !(pkt->flags & UDX_HEADER_SACK)) {
        // ws_info("mtu probe found");
        expert_add_info(pinfo, data_item, &ei_udx_mtu_mtuprobe);
    }

    // todo: tap info
    // udx_tap_cleanup_t *cleanup = wmem_new(pinfo->pool, udx_tap_cleanup_t);
    // cleanup->pinfo = pinfo;
    // cleanup->pkt = pkt;
    // CLEANUP_PUSH(udx_tap_cleanup, cleanup);

    // todo: completeness info

    proto_item_set_len(udx_tree, 20);

    if (pkt->flags & UDX_HEADER_END) {
        expert_add_info(pinfo, tf_end, &ei_udx_connection_end);

        if (!stream->rev->is_closing_initiator) {
            stream->fwd->is_closing_initiator = true;
            expert_add_info(pinfo, tf_end, &ei_udx_connection_end_active);
        } else {
            expert_add_info(pinfo, tf_end, &ei_udx_connection_end_passive);
        }
    }

    if (pkt->flags & UDX_HEADER_DESTROY) {
        expert_add_info(pinfo, tf_destroy, &ei_udx_connection_destroy);
    }

    if (udx_calculate_ts) {
        udx_print_timestamps(pinfo, tvb, udx_tree, stream, udxppd);
    }

    udx_print_sequence_number_analysis(pinfo, tvb, udx_tree, stream, pkt->seq, pkt->ack);

    uint32_t captured_length_remaining = tvb_captured_length_remaining(tvb, 20);

    if (pkt->flags & UDX_HEADER_DATA && captured_length_remaining != 0) {
        // todo: sub dissector
        ;
    }

    if (!pinfo->fd->visited && stream && stream->acked_info &&
        udx_write_stream_dat_file && stream->file != NULL) {

        nstime_t relative_ts;
        nstime_delta(&relative_ts, &pinfo->abs_ts, &stream->ts_first);

        uint64_t time_ms = relative_ts.secs * 1000 + (relative_ts.nsecs / 1000000);

        fprintf(stream->file, "%lu %u\n", time_ms, stream->acked_info->bytes_in_flight);
    }

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}

static void
udx_init (void) { ; }

static void
udx_cleanup (void) { ; }

// register_follow_stream(proto_udx,
//     "udx_follow",
//     udx_follow_conv_filter,
//     udx_follow_index_filter,
//     udx_follow_address_filter,
//      udx_port_to_display,
//       follow_udx_tap_listener,
//        get_udx_stream_count,
//         NULL);

// follow conversation callbacks

char *
udx_follow_conv_filter (epan_dissect_t *edt _U_, packet_info *pinfo, uint32_t *streamid, uint32_t *sub_stream _U_) {
    conversation_t *conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst, CONVERSATION_UDX, pinfo->srcport, pinfo->destport, 0);
    if (!conv) return NULL;

    udx_stream_t *stream = (udx_stream_t *) conversation_get_proto_data(conv, proto_udx);

    if (!stream) return NULL;

    udx_per_packet_data_t *udxppd = (udx_per_packet_data_t *) p_get_proto_data(wmem_file_scope(), pinfo, proto_udx, 0);
    ws_info("udxppd=%p", udxppd);

    if (!udxppd) return NULL;

    uint32_t id = udxppd->stream;
    *streamid = id;

    ws_info("udx_follow_conv_filter id=%u", id);
    return ws_strdup_printf("udx.stream eq %u", id);
}

char *
udx_follow_index_filter (uint32_t stream, uint32_t sub_stream _U_) {
    ws_info("udx_follow_index_filter");
    return ws_strdup_printf("udx.stream eq %u", stream);
}

char *
udx_follow_address_filter (address *src_addr, address *dst_addr, int src_port, int dst_port) {
    ws_info("udx_follow_address_filter");

    const gchar *ip_version = src_addr->type == AT_IPv6 ? "v6" : "";
    gchar src_addr_str[WS_INET6_ADDRSTRLEN];
    gchar dst_addr_str[WS_INET6_ADDRSTRLEN];

    address_to_str_buf(src_addr, src_addr_str, sizeof(src_addr_str));
    address_to_str_buf(dst_addr, dst_addr_str, sizeof(dst_addr_str));

    return ws_strdup_printf("((ip%s.src eq %s and tcp.srcport eq %d) and "
                            "(ip%s.dst eq %s and tcp.dstport eq %d))"
                            " or "
                            "((ip%s.src eq %s and tcp.srcport eq %d) and "
                            "(ip%s.dst eq %s and tcp.dstport eq %d))",
                            ip_version,
                            src_addr_str,
                            src_port,
                            ip_version,
                            dst_addr_str,
                            dst_port,
                            ip_version,
                            dst_addr_str,
                            dst_port,
                            ip_version,
                            src_addr_str,
                            src_port);
}

typedef struct {
    tvbuff_t *tvb;
    udx_packet_t *pkt;
    udx_stream_t *stream;
} udx_follow_tap_data_t;

static tap_packet_status
follow_udx_tap_listener (void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_) {
    ws_info("follow_udx_tap_listener");

    follow_info_t *follow_info = (follow_info_t *) tapdata;
    udx_follow_tap_data_t *follow_data = (udx_follow_tap_data_t *) data;

    uint32_t seq = follow_data->pkt->seq;
    uint32_t len = follow_data->pkt->payload_len;
    uint32_t data_offset = 20;
    uint32_t data_length = tvb_captured_length(follow_data->tvb);

    // we'll consider the person we see send data first the 'client' for follow_info->client_*

    if (follow_info->client_port == 0) {
        follow_info->client_port = pinfo->srcport;
        copy_address(&follow_info->client_ip, &pinfo->src);
        follow_info->server_port = pinfo->destport;
        copy_address(&follow_info->server_ip, &pinfo->dst);
    }

    bool is_server = !(addresses_equal(&follow_info->client_ip, &pinfo->src) && follow_info->client_port == pinfo->srcport);

    if (follow_info->bytes_written[is_server] == 0 && follow_info->seq[is_server] == 0) {
        follow_info->seq[is_server] = seq;
    }

    // for now, let's bail if we see a gap (don't keep OOO buffer)

    // if (lt_seq(seq, follow_info->seq[is_server])) {
    // ws_info("sequence may cover a gap (todo)");
    // }

    ws_info("follow_tap: seq=%u len=%u data_offset=%u data_length=%u", seq, len, data_offset, data_length);

    if (len == 0 || lt_seq(seq, follow_info->seq[is_server])) {
        return TAP_PACKET_DONT_REDRAW;
    }

    follow_record_t *follow_record = g_new0(follow_record_t, 1);
    follow_record->is_server = is_server;
    follow_record->packet_num = pinfo->fd->num;
    follow_record->abs_ts = pinfo->fd->abs_ts;
    follow_record->seq = seq; /* start of fragment, used by check_follow_fragments. */
    follow_record->data = g_byte_array_append(g_byte_array_new(), tvb_get_ptr(follow_data->tvb, data_offset, data_length), data_length);

    if (seq == follow_info->seq[is_server]) {
        follow_info->seq[is_server] = seq + 1;
        follow_info->bytes_written[is_server] += follow_record->data->len;
        follow_info->payload = g_list_prepend(follow_info->payload, follow_record);

        // while(check_follow_fragments(follow_info, is_server, 0, pinfo->fd->num, false));
    } else {
        ws_warning("missing data in tap!");
        // follow_info->fragments[is_server] = g_list_append(follow_info->fragments[is_server], follow_record);
        return TAP_PACKET_FAILED;
    }

    return TAP_PACKET_DONT_REDRAW;
}

static uint32_t
get_udx_stream_count (void) {
    return udx_stream_count;
}

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_udx (void) {
    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */

    static hf_register_info hf[] = {
        {
            &hf_udx_magic_byte,
            {"UDX Magic Byte", "udx.magic_byte", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL},
        },
        {
            &hf_udx_version,
            {"Version", "udx.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL},
        },
        {&hf_udx_flags,
         {"UDX Flags", "udx.flags", FT_UINT8, BASE_HEX, NULL, 0x1f, "The flags set in the UDX header", HFILL}},
        {
            &hf_udx_flags_data,
            {"Data", "udx.flags.data", FT_BOOLEAN, 5, TFS(&tfs_set_notset), UDX_HEADER_DATA, "This flag indicates the packet has a payload", HFILL},
        },
        {
            &hf_udx_flags_end,
            {"End", "udx.flags.end", FT_BOOLEAN, 5, TFS(&tfs_set_notset), UDX_HEADER_END, NULL, HFILL},
        },
        {
            &hf_udx_flags_sack,
            {"SACK", "udx.flags.sack", FT_BOOLEAN, 5, TFS(&tfs_set_notset), UDX_HEADER_SACK, NULL, HFILL},
        },
        {
            &hf_udx_flags_message,
            {"Message", "udx.flags.message", FT_BOOLEAN, 5, TFS(&tfs_set_notset), UDX_HEADER_MESSAGE, NULL, HFILL},
        },
        {
            &hf_udx_flags_destroy,
            {"Destroy", "udx.flags.destroy", FT_BOOLEAN, 5, TFS(&tfs_set_notset), UDX_HEADER_DESTROY, NULL, HFILL},
        },
        {
            &hf_udx_data_offset,
            {"Data Offset", "udx.offset", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL},
        },
        {
            &hf_udx_id,
            {"Id", "udx.id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL},
        },
        {
            &hf_udx_window,
            {"Window", "udx.window", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL},
        },
        {
            &hf_udx_seq,
            {"Sequence", "udx.seq", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL},
        },
        {&hf_udx_ack,
         {"Ack", "udx.ack", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_udx_sack_start,
         {"Sack start", "udx.sack.start", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_udx_sack_end,
         {"Sack end", "udx.sack.end", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_udx_analysis,
         {"SEQ/ACK analysis", "udx.analysis", FT_NONE, BASE_NONE, NULL, 0x0, "This frame has some SEQ/ACK analysis info", HFILL}},
        {&hf_udx_analysis_flags,
         {"UDX Analysis Flags", "udx.analysis.flags", FT_NONE, BASE_NONE, NULL, 0x0, "This frame has some of the UDX analysis flags set", HFILL}},
        {&hf_udx_analysis_duplicate_ack,
         {"Duplicate ACK", "udx.analysis.duplicate_ack", FT_NONE, BASE_NONE, NULL, 0x0, "This is a duplicate ack", HFILL}},
        {&hf_udx_analysis_duplicate_ack_num,
         {"Duplicate ACK #", "udx.analysis.duplicate_ack_num", FT_UINT32, BASE_DEC, NULL, 0x0, "This is duplicate ack #", HFILL}},
        {&hf_udx_analysis_duplicate_ack_frame,
         {"Duplicate to the ACK in frame", "udx.analysis.duplicate_ack_frame", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_DUP_ACK), 0x0, "this is a duplicate to the ACK in frame #", HFILL}},
        {&hf_udx_analysis_acks_frame,
         {"This is an ACK to the packet in frame", "udx.analysis.acks_frame", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_ACK), 0x0, "Which previous packet is this an ACK for", HFILL}},
        {&hf_udx_analysis_bytes_in_flight,
         {"Bytes in flight", "udx.analysis.bytes_in_flight", FT_UINT32, BASE_DEC, NULL, 0x0, "Bytes are now in flight for this stream", HFILL}},
        {&hf_udx_analysis_ack_rtt,
         {"the RTT to ACK the segment was", "udx.analysis.ack_rtt", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, "How long it took to ACK the segment (RTT)", HFILL}},
        {&hf_udx_analysis_first_rtt,
         {"iRTT", "udx.analysis.first_rtt", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, "how long the first packet took to be acked", HFILL}},
        {&hf_udx_analysis_rto,
         {"how long before this segment was retransmitted", "udx.analysis.rto", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, "How long retransmission was delayed", HFILL}},
        {&hf_udx_analysis_rto_frame,
         {"RTO based on delta from frame", "udx.analsysis.rto_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, "This is the frame we measured the retransmit delay from", HFILL}},
        {&hf_udx_payload,
         {"Payload", "udx.payload", FT_BYTES, BASE_NONE, NULL, 0x0, "The UDX payload of this packet", HFILL}},
        {&hf_udx_stream,
         {"Stream Number", "udx.stream", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_udx_stream_pnum,
         {"Stream Packet Number", "udx.stream.pnum", FT_UINT32, BASE_DEC, NULL, 0x0, "Relative packet number in this UDX stream", HFILL}},
        {&hf_udx_ts_relative,
         {"Time since first frame in  this stream", "udx.time_relative", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, "Time since last packet in this UDX stream", HFILL}},
        {&hf_udx_ts_delta,
         {"Time since previous frame in this UDX stream", "udx.time_delta", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, "Time delta from previous frame in this UDX stream", HFILL}}
    };

    /* Setup protocol subtree array */
    static int *ett[] = {&ett_udx, &ett_udx_completeness, &ett_udx_flags, &ett_udx_sack, &ett_udx_analysis, &ett_udx_timestamps};

    /* Setup protocol expert items */

    static ei_register_info ei[] = {
        {&ei_udx_analysis_retransmission,
         {"udx.analysis.retransmission", PI_SEQUENCE, PI_WARN, "packet is retransmitted", EXPFILL}},
        {&ei_udx_analysis_fast_retransmission,
         {"udx.analysis.fast_retransmission", PI_SEQUENCE, PI_NOTE, "packet is a suspected fast retransmission", EXPFILL}},
        {&ei_udx_analysis_spurious_retransmission,
         {"udx.analysis.spurious_retransmission", PI_SEQUENCE, PI_NOTE, "packet is a spurious retransmission", EXPFILL}},
        {&ei_udx_analysis_lost_packet,
         {
             "udx.analysis.lost_packet",
             PI_SEQUENCE,
             PI_WARN,
             "Previous packet not captured (common at capture start)",
             EXPFILL,
         }},
        {&ei_udx_analysis_ack_lost_packet,
         {
             "udx.analysis.ack_lost_packet",
             PI_SEQUENCE,
             PI_WARN,
             "ACKed packet not captured (common at capture start)",
             EXPFILL,
         }},
        {&ei_udx_connection_end,
         {"udx.connection.end", PI_SEQUENCE, PI_NOTE, "packet ends traffic in this direction", EXPFILL}},
        {&ei_udx_connection_end_active,
         {"udx.connection.end_active", PI_SEQUENCE, PI_NOTE, "This frame initiates the connection closing", EXPFILL}},
        {&ei_udx_connection_end_passive,
         {"udx.connection.end_passive", PI_SEQUENCE, PI_NOTE, "This frame undergoes the connection closing", EXPFILL}},
        {&ei_udx_connection_destroy,
         {"udx.connection.destroy", PI_SEQUENCE, PI_WARN, "this frame destroys the connection", EXPFILL}},
        {&ei_udx_mtu_mtuprobe,
         {"udx.mtuprobe", PI_COMMENTS_GROUP, PI_CHAT, "packet is an MTU probe", EXPFILL}}
    };

    /* Register the protocol name and description */
    proto_udx = proto_register_protocol("UDX", "UDX", "udx");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_udx, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_module_t *expert_udx = expert_register_protocol(proto_udx);
    expert_register_field_array(expert_udx, ei, array_length(ei));

    /* Use register_dissector() here so that the dissector can be
     * found by name by other protocols, by Lua, by Export PDU,
     * by custom User DLT dissection, etc. Some protocols may require
     * multiple uniquely named dissectors that behave differently
     * depending on the caller, e.g. over TCP directly vs over TLS.
     */
    udx_handle = register_dissector("udx", dissect_udx, proto_udx);

    /* Register a preferences module (see section 2.6 of README.dissector
     * for more details). Registration of a prefs callback is not required
     * if there are no preferences that affect protocol registration (an example
     * of a preference that would affect registration is a port preference).
     * If the prefs callback is not needed, use NULL instead of
     * proto_reg_handoff_udx in the following.
     */

    module_t *udx_module =
        prefs_register_protocol(proto_udx, proto_reg_handoff_udx);

    // /* Register a simple example preference */
    prefs_register_bool_preference(
        udx_module, "write_stream_dat_file", "write stream .dat files", "Enable to write stream-%u.dat files to /tmp for graphing", &udx_write_stream_dat_file
    );

    register_follow_stream(proto_udx, "udx_follow", udx_follow_conv_filter, udx_follow_index_filter, udx_follow_address_filter, udp_port_to_display, follow_udx_tap_listener, get_udx_stream_count, NULL);

    register_init_routine(udx_init);
    register_cleanup_routine(udx_cleanup);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */

static bool
dissect_udx_heur (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    if (!test_udx_packet(tvb)) {
        return false;
    }

    conversation_t *udp_conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(udp_conversation, udx_handle);

    dissect_udx(tvb, pinfo, tree, data);
    return true;
}

void
proto_reg_handoff_udx (void) {

    // 1. create dissector handle
    udx_handle = create_dissector_handle(dissect_udx, proto_udx);

    // 2. register heuristic dissector
    // todo: comment out if heuristic is too aggressive

    heur_dissector_add("udp", dissect_udx_heur, "UDX", "udx", proto_udx, HEURISTIC_ENABLE);

    // 3. register as a normal dissector so we can apply it manually.
    // might be useful in instances where 'socket' send/recv is used on a
    // connection to send non-udx packets, causing our heuristic to be passed
    // over.

    dissector_add_uint("udp.port", UDX_PORT, udx_handle);

    // udx_tap = register_tap("udx");
    udx_follow_tap = register_tap("udx_follow");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
