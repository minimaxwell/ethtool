/*
 * phy.c - List PHYs on an interface and their parameters
 *
 * Implementation of "ethtool --show-phys <dev>"
 */

#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "parser.h"

/* PHY_GET / PHY_DUMP */

static const char * phy_upstream_type_to_str(uint8_t upstream_type)
{
	switch (upstream_type) {
	case PHY_UPSTREAM_PHY: return "PHY";
	case PHY_UPSTREAM_MAC: return "MAC";
	default: return "Unknown";
	}
}

int phy_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_PHY_MAX + 1] = {};
	struct nl_context *nlctx = data;
	DECLARE_ATTR_TB_INFO(tb);
	uint8_t upstream_type;
	bool silent;
	int err_ret;
	int ret;

	silent = nlctx->is_dump || nlctx->is_monitor;
	err_ret = silent ? MNL_CB_OK : MNL_CB_ERROR;
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return err_ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_PHY_HEADER]);
	if (!dev_ok(nlctx))
		return err_ret;

	if (silent)
		print_nl();

	open_json_object(NULL);

	print_string(PRINT_ANY, "ifname", "PHY for %s:\n", nlctx->devname);

	show_u32("phy_index", "PHY index: ", tb[ETHTOOL_A_PHY_INDEX]);

	if (tb[ETHTOOL_A_PHY_DRVNAME])
		print_string(PRINT_ANY, "drvname", "Driver name: %s\n",
		     mnl_attr_get_str(tb[ETHTOOL_A_PHY_DRVNAME]));

	if (tb[ETHTOOL_A_PHY_NAME])
		print_string(PRINT_ANY, "name", "PHY device name: %s\n",
		     mnl_attr_get_str(tb[ETHTOOL_A_PHY_NAME]));

	if (tb[ETHTOOL_A_PHY_DOWNSTREAM_SFP_NAME])
		print_string(PRINT_ANY, "downstream_sfp_name",
			     "Downstream SFP bus name: %s\n",
			     mnl_attr_get_str(tb[ETHTOOL_A_PHY_DOWNSTREAM_SFP_NAME]));

	if (tb[ETHTOOL_A_PHY_ID])
		show_u32("phy_id", "PHY id: ", tb[ETHTOOL_A_PHY_ID]);

	if (tb[ETHTOOL_A_PHY_UPSTREAM_TYPE]) {
		upstream_type = mnl_attr_get_u8(tb[ETHTOOL_A_PHY_UPSTREAM_TYPE]);
		print_string(PRINT_ANY, "upstream_type", "Upstream type: %s\n",
			     phy_upstream_type_to_str(upstream_type));
	}

	if (tb[ETHTOOL_A_PHY_UPSTREAM_INDEX])
		show_u32("upstream_index", "Upstream PHY index: ",
			 tb[ETHTOOL_A_PHY_UPSTREAM_INDEX]);

	if (tb[ETHTOOL_A_PHY_UPSTREAM_SFP_NAME])
		print_string(PRINT_ANY, "upstream_sfp_name", "Upstream SFP name: %s\n",
			     mnl_attr_get_str(tb[ETHTOOL_A_PHY_UPSTREAM_SFP_NAME]));

	if (tb[ETHTOOL_A_PHY_LOOPBACK])
		show_bool("loopback", "loopback : %s\n", tb[ETHTOOL_A_PHY_LOOPBACK]);

	if (tb[ETHTOOL_A_PHY_ISOLATE])
		show_bool("isolate", "isolate :%s\n", tb[ETHTOOL_A_PHY_ISOLATE]);

	if (!silent)
		print_nl();

	close_json_object();

	return MNL_CB_OK;

err:
	close_json_object();
	return err_ret;
}

int nl_get_phy(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	u32 flags;
	int ret;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_PHY_GET, true))
		return -EOPNOTSUPP;
	if (ctx->argc > 0) {
		fprintf(stderr, "ethtool: unexpected parameter '%s'\n",
			*ctx->argp);
		return 1;
	}

	ret = nlsock_prep_filtered_dump_request(nlsk, ETHTOOL_MSG_PHY_GET,
						ETHTOOL_A_PHY_HEADER, flags);
	if (ret)
		return ret;

	new_json_obj(ctx->json);
	ret = nlsock_send_get_request(nlsk, phy_reply_cb);
	delete_json_obj();
	return ret;
}

static const struct param_parser phy_set_params[] = {
	{
		.arg		= "loopback",
		.type		= ETHTOOL_A_PHY_LOOPBACK,
		.handler	= nl_parse_u8bool,
		.min_argc	= 1,
	},
	{
		.arg		= "isolate",
		.type		= ETHTOOL_A_PHY_ISOLATE,
		.handler	= nl_parse_u8bool,
		.min_argc	= 1,
	},
	{}
};

int nl_set_phy(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_msg_buff *msgbuff;
	struct nl_socket *nlsk;
	int ret;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_PHY_SET, false))
		return -EOPNOTSUPP;

	nlctx->cmd = "--set-phy";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	nlctx->devname = ctx->devname;
	nlsk = nlctx->ethnl_socket;
	msgbuff = &nlsk->msgbuff;

	ret = msg_init(nlctx, msgbuff, ETHTOOL_MSG_PHY_SET,
		       NLM_F_REQUEST | NLM_F_ACK);
	if (ret)
		return ret;

	if (ethnla_fill_header_phy(msgbuff, ETHTOOL_A_PHY_HEADER,
				   ctx->devname, ctx->phy_index, 0))
		return -EMSGSIZE;

	ret = nl_parser(nlctx, phy_set_params, NULL, PARSER_GROUP_NONE, NULL);
	if (ret)
		return ret;

	ret = nlsock_sendmsg(nlsk, NULL);
	if (ret < 0)
		return ret;

	ret = nlsock_process_reply(nlsk, nomsg_reply_cb, nlctx);
	if (ret)
		return nlctx->exit_code;

	return ret;
}
