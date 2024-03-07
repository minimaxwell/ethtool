/*
 * phy.c - List PHYs on an interface and their parameters
 *
 * Implementation of "ethtool --show-ports <dev> | --set-port <dev>"
 */

#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "parser.h"

/* PORT_GET / PORT_DUMP */
const char *port_type_to_str(u32 port_type)
{
	/* TODO */
	return "phy";
}

const char *port_state_to_str(u32 port_state)
{
	/* TODO */
	return "N/A";
}

int port_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_PORT_MAX + 1] = {};
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
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_PORT_HEADER]);
	if (!dev_ok(nlctx))
		return err_ret;

	if (silent)
		print_nl();

	open_json_object(NULL);

	print_string(PRINT_ANY, "ifname", "Port for %s:\n", nlctx->devname);

	show_u32("port_id", "Port id: ", tb[ETHTOOL_A_PORT_ID]);
	print_string(PRINT_ANY, "port_type", "Port type: %s\n",
		     port_type_to_str(mnl_attr_get_u32(tb[ETHTOOL_A_PORT_TYPE])));

	if (tb[ETHTOOL_A_PORT_ENABLED])
		show_bool("enabled", "enabled : %s\n", tb[ETHTOOL_A_PORT_ENABLED]);
	if (tb[ETHTOOL_A_PORT_FORCED])
		show_bool("forced", "forced : %s\n", tb[ETHTOOL_A_PORT_FORCED]);

	if (tb[ETHTOOL_A_PORT_STATE])
		print_string(PRINT_ANY, "port_type", "Port type: %s\n",
			     port_state_to_str(mnl_attr_get_u32(tb[ETHTOOL_A_PORT_STATE])));

	if (!silent)
		print_nl();

	close_json_object();

	return MNL_CB_OK;

err:
	close_json_object();
	return err_ret;
}

int nl_get_port(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	u32 flags;
	int ret;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_PORT_GET, true))
		return -EOPNOTSUPP;
	if (ctx->argc > 0) {
		fprintf(stderr, "ethtool: unexpected parameter '%s'\n",
			*ctx->argp);
		return 1;
	}

	ret = nlsock_prep_filtered_dump_request(nlsk, ETHTOOL_MSG_PORT_GET,
						ETHTOOL_A_PORT_HEADER, flags);
	if (ret)
		return ret;

	new_json_obj(ctx->json);
	ret = nlsock_send_get_request(nlsk, port_reply_cb);
	delete_json_obj();
	return ret;
}

static const struct param_parser phy_set_params[] = {
	{
		.arg		= "port",
		.type		= ETHTOOL_A_PORT_ID,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{
		.arg		= "enable",
		.type		= ETHTOOL_A_PORT_ENABLED,
		.handler	= nl_parse_u8bool,
		.min_argc	= 1,
	},
	{
		.arg		= "force",
		.type		= ETHTOOL_A_PORT_FORCED,
		.handler	= nl_parse_u8bool,
		.min_argc	= 1,
	},
	{}
};

int nl_set_port(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_msg_buff *msgbuff;
	struct nl_socket *nlsk;
	int ret;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_PORT_SET, false))
		return -EOPNOTSUPP;

	nlctx->cmd = "--set-port";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	nlctx->devname = ctx->devname;
	nlsk = nlctx->ethnl_socket;
	msgbuff = &nlsk->msgbuff;

	ret = msg_init(nlctx, msgbuff, ETHTOOL_MSG_PORT_SET,
		       NLM_F_REQUEST | NLM_F_ACK);
	if (ret)
		return ret;

	if (ethnla_fill_header(msgbuff, ETHTOOL_A_PORT_HEADER, ctx->devname, 0))
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
