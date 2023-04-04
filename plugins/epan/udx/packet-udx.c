#include "config.h"
#include <epan/packet.h>
//#include <epan/expert.h>
#include <epan/conversation.h>

static int proto_udx             = -1;
static dissector_handle_t udx_handle;

static int hf_udx_magic_byte     = -1;
static int hf_udx_version        = -1;
static int hf_udx_type           = -1;
static int hf_udx_data_offset    = -1;
static int hf_udx_id             = -1;
static int hf_udx_window         = -1;
static int hf_udx_seqno          = -1;
static int hf_udx_ack            = -1;
static int hf_udx_sack_start     = -1;
static int hf_udx_sack_end       = -1;
static int hf_udx_payload        = -1;

static int hf_udx_type_data      = -1;
static int hf_udx_type_end       = -1;
static int hf_udx_type_sack      = -1;
static int hf_udx_type_message   = -1;
static int hf_udx_type_destroy   = -1;



static int ett_udx               = -1;

#define UDX_HEADER_DATA    0b00001
#define UDX_HEADER_END     0b00010
#define UDX_HEADER_SACK    0b00100
#define UDX_HEADER_MESSAGE 0b01000
#define UDX_HEADER_DESTROY 0b10000

static hf_register_info hf[] = {
    {
        &hf_udx_magic_byte,
        {
            "UDX Magic Byte",
            "udx.magic_byte",
            FT_UINT8,
            BASE_HEX,
            NULL,
            0x0,
            NULL,
            HFILL
        },
    }, {
        &hf_udx_version,
        {
            "Version",
            "udx.version",
            FT_UINT8,
            BASE_DEC,
            NULL,
            0x0,
            NULL,
            HFILL
        },
    }, {
        &hf_udx_type,
        {
            "Type",
            "udx.type",
            FT_UINT8,
            BASE_HEX,
            NULL,
            0x0,
            NULL,
            HFILL
        },
    }, {
        &hf_udx_type_data,
        {
            "Data",
            "udx.type.data",
            FT_BOOLEAN,
            8,
            NULL,
            UDX_HEADER_DATA,
            NULL,
            HFILL
        },
    }, {
         &hf_udx_type_end,
        {
            "End",
            "udx.type.end",
            FT_BOOLEAN,
            8,
            NULL,
            UDX_HEADER_END,
            NULL,
            HFILL
        },
    }, {
         &hf_udx_type_sack,
        {
            "SACK",
            "udx.type.sack",
            FT_BOOLEAN,
            8,
            NULL,
            UDX_HEADER_SACK,
            NULL,
            HFILL
        },
    }, {
         &hf_udx_type_message,
        {
            "Message",
            "udx.type.message",
            FT_BOOLEAN,
            8,
            NULL,
            UDX_HEADER_MESSAGE,
            NULL,
            HFILL
        },
    }, {
         &hf_udx_type_destroy,
        {
            "Destroy",
            "udx.type.destroy",
            FT_BOOLEAN,
            8,
            NULL,
            UDX_HEADER_DESTROY,
            NULL,
            HFILL
        },
    }, {
        &hf_udx_data_offset,
        {
            "Data Offset",
            "udx.offset",
            FT_UINT8,
            BASE_HEX,
            NULL,
            0x0,
            NULL,
            HFILL
        },
    }, {
        &hf_udx_id,
        {
            "Id",
            "udx.id",
            FT_UINT32,
            BASE_DEC,
            NULL,
            0x0,
            NULL,
            HFILL
        },
    }, {
        &hf_udx_window,
        {
            "Window",
            "udx.window",
            FT_UINT32,
            BASE_DEC,
            NULL,
            0x0,
            NULL,
            HFILL
        },
    }, {
        &hf_udx_seqno,
        {
            "Sequence",
            "udx.seq",
            FT_UINT32,
            BASE_DEC,
            NULL,
            0x0,
            NULL,
            HFILL
        },
    }, {
        &hf_udx_ack,
        {
            "Ack",
            "udx.ack",
            FT_UINT32,
            BASE_DEC,
            NULL,
            0x0,
            NULL,
            HFILL
        }
    }, {
        &hf_udx_sack_start, 
        {
            "Sack start",
            "udx.sack.start",
            FT_UINT32,
            BASE_DEC,
            NULL,
            0x0,
            NULL,
            HFILL
        }
    }, {
        &hf_udx_sack_end, 
        {
            "Sack end",
            "udx.sack.end",
            FT_UINT32,
            BASE_DEC,
            NULL,
            0x0,
            NULL,
            HFILL
        }
    }, {
        &hf_udx_payload,
        {
            "Payload",
            "udx.payload",
            FT_BYTES,
            BASE_NONE,
            NULL, 0x0, NULL, HFILL
        }
    }
};

static gint *ett[] = {
    &ett_udx
};

//static expert_field ei_udx_duplicate_ack = EI_INIT;
//static expert_field ei_udx_duplicate_seq = EI_INIT;


WS_DLL_PUBLIC_DEF const gchar plugin_version[] = "0.0.0";
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);

#define UDX_PORT -1


static int
dissect_udx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    static int * const type_flags[] = {
        &hf_udx_type_data,
        &hf_udx_type_end,
        &hf_udx_type_sack,
        &hf_udx_type_message,
        &hf_udx_type_destroy,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDX");
    col_clear(pinfo->cinfo, COL_INFO);

    guint8 pkt_type = tvb_get_guint8(tvb, 2);
    struct { int i; char *s; } lookup [] = {
        { UDX_HEADER_DATA, "Data"},
        { UDX_HEADER_END, "End"},
        { UDX_HEADER_SACK, "Sack"},
        { UDX_HEADER_MESSAGE, "Message"},
        { UDX_HEADER_DESTROY, "Destroy"},
    };

    

    proto_item *ti = proto_tree_add_item(tree, proto_udx, tvb, 0, -1, ENC_NA);

    proto_tree *udx_tree = proto_item_add_subtree(ti, ett_udx);

    proto_tree_add_item(udx_tree, hf_udx_magic_byte,           tvb, 0,  1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(udx_tree, hf_udx_version,              tvb, 1,  1, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(udx_tree,                           tvb, 2, hf_udx_type, ett_udx, type_flags, ENC_NA);

    guint32 data_offset, id, window, seq, ack;
    proto_tree_add_item_ret_uint(udx_tree, hf_udx_data_offset, tvb, 3,  1, ENC_LITTLE_ENDIAN, &data_offset);
    proto_tree_add_item_ret_uint(udx_tree, hf_udx_id,          tvb, 4,  4, ENC_LITTLE_ENDIAN, &id);
    proto_tree_add_item_ret_uint(udx_tree, hf_udx_window,      tvb, 8,  4, ENC_LITTLE_ENDIAN, &window);

    proto_tree_add_item_ret_uint(udx_tree, hf_udx_seqno,       tvb, 12, 4, ENC_LITTLE_ENDIAN, &seq);
    proto_tree_add_item_ret_uint(udx_tree, hf_udx_ack,         tvb, 16, 4, ENC_LITTLE_ENDIAN, &ack);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%u → %u Id=%u Seq=%u Ack=%u ", pinfo->srcport, pinfo->destport, id, seq, ack);

    if (pkt_type == 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Ack");
    }

    for (unsigned int i = 0; i < (sizeof(lookup) / sizeof(lookup[0])); i++) {
        if (pkt_type & lookup[i].i) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",lookup[i].s);
        }
    }
    
    unsigned int offset = 20;

    if (pkt_type & UDX_HEADER_SACK) {
        unsigned int header_end = data_offset ? 20u + data_offset : tvb_captured_length(tvb);
        col_append_str(pinfo->cinfo, COL_INFO, "Sack=");
        while (offset+8 <= header_end) {
            unsigned int sack_start, sack_end;
            proto_tree_add_item_ret_uint(udx_tree, hf_udx_sack_start, tvb, offset,     4, ENC_LITTLE_ENDIAN, &sack_start);
            proto_tree_add_item_ret_uint(udx_tree, hf_udx_sack_end,   tvb, offset + 4, 4, ENC_LITTLE_ENDIAN, &sack_end);

            col_append_fstr(pinfo->cinfo, COL_INFO, "%u-%u ", sack_start, sack_end);

            offset += 8;
        }
    }

    if (tvb_captured_length(tvb) > offset) {
        proto_tree_add_item(udx_tree, hf_udx_payload,     tvb, offset, -1, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

static gboolean
test_udx(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
    /* minimum size (for headers) */
    if (tvb_captured_length(tvb)<20) {
        return FALSE;
    }

    /* first byte 0xff */
    if (tvb_get_guint8(tvb, 0) != 0xff) {
        return FALSE;
    }

    /* second byte version, we only understand version 1 */
    if (tvb_get_guint8(tvb, 1) != 0x01) {
        return FALSE;
    }

    /* only the 5 lsb are used for flags in version 1 */
    guint8 flags = tvb_get_guint8(tvb, 2);
    if ( flags & 0xE0) {
        return FALSE;
    }

    /* if data_offset is set packet size must be at least header length + data_offset */
    guint8 data_offset = tvb_get_guint8(tvb, 3);
    if (data_offset > 0 && tvb_captured_length(tvb) < (20u + data_offset)) {
        return FALSE;
    }

    /* should a packet containing a UDX_HEADER_MESSAGE be allowed to have any other (stream?) flags? */ 

    // if (flags & UDX_HEADER_MESSAGE && flags & ~UDX_HEADER_MESSAGE) {
    //     return FALSE;
    // }
    
    
    return TRUE;
    
}

void proto_register_udx(void)
{
    /*
    static ei_register_info ei[] = {
        {
            &ei_udx_duplicate_seq,
            { "udx.dup_seq", PI_SEQUENCE, PI_CHAT, "duplicate seq", EXPFILL }
        }, {
            &ei_udx_duplicate_ack,
            { "udx.dup_ack", PI_SEQUENCE, PI_CHAT, "duplicate ack", EXPFILL }
        },
    };
    */
    
    proto_udx = proto_register_protocol(
        "UDX Protocol", /* name */
        "UDX", /* short name */
        "udx"  /* filter_name */
    );

    proto_register_field_array(proto_udx, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    // expert_module_t *expert_udx = expert_register_protocol(proto_udx);
    // expert_register_field_array(expert_udx, ei, array_length(ei));
}

static gboolean
dissect_udx_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!test_udx(pinfo, tvb, 0, data)) {
        return FALSE;
    }
    conversation_t *conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, udx_handle);

    dissect_udx(tvb, pinfo, tree, data);
    return (TRUE);
}

// maps handler -> protocol traffic
void proto_reg_handoff_udx(void)
{

    // 1. create dissector handle
    udx_handle = create_dissector_handle(dissect_udx, proto_udx);

    // 2. register heuristic dissector
    // todo: comment out if heuristic is too aggressive

    heur_dissector_add("udp", dissect_udx_heur, "UDX", "udx", proto_udx, HEURISTIC_ENABLE);

    // 3. register as a normal dissector so we can apply it manually.
    // might be useful in instances where 'socket' send/recv is used on a connection
    // to send non-udx packets, causing our heuristic to be passed over.

    dissector_add_uint("udp.port", UDX_PORT, udx_handle);

}

void plugin_register(void)
{
    static proto_plugin plug;

    plug.register_protoinfo = proto_register_udx;
    plug.register_handoff = proto_reg_handoff_udx;
    proto_register_plugin(&plug);
}
