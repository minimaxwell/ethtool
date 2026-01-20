/*
 * port.c - netlink implementation of Network port
 *
 * Implementation of "ethtool --show-port <dev>"
 */

#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "bitset.h"

static const char *port_type_str(unsigned int port_type)
{
	switch (port_type) {
	case ETHTOOL_PORT_TYPE_MDI: return "mdi";
	case ETHTOOL_PORT_TYPE_SFP: return "sfp";
	default: return "unknown";
	}
}

/* PORT_GET */
static void port_interfaces_walk_cb(unsigned int idx, const char *name,
				    bool val, void *data)
{
	bool *first = data;

	if (!val)
		return;

	if (!*first)
		putchar(',');
	*first = false;

	printf(" %s", name);
}

int port_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_PORT_MAX + 1] = {};
	struct nl_context *nlctx = data;
	uint8_t port_type, vacant;
	DECLARE_ATTR_TB_INFO(tb);
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

	show_u32("port_id", "\tPort id: ", tb[ETHTOOL_A_PORT_ID]);

	vacant = mnl_attr_get_u8(tb[ETHTOOL_A_PORT_VACANT]);
	print_string(PRINT_ANY, "vacant", "\tVacant: %s\n",
		     vacant ? "yes" : "no");

	if (tb[ETHTOOL_A_PORT_SUPPORTED_MODES]) {
		ret = dump_link_modes(nlctx, tb[ETHTOOL_A_PORT_SUPPORTED_MODES],
				      false, LM_CLASS_REAL,
				      "Supported link modes:  ", NULL, "\n",
				      "Not reported", "supported-link-modes");
		if (ret < 0)
			return err_ret;
	}

	if (tb[ETHTOOL_A_PORT_SUPPORTED_INTERFACES]) {
		bool first = true;

		printf("\tSupported MII interfaces :");
		ret = walk_bitset(tb[ETHTOOL_A_PORT_SUPPORTED_INTERFACES], NULL,
				  port_interfaces_walk_cb, &first);
		if (ret < 0)
			return err_ret;
		printf("\n");

	}

	port_type = mnl_attr_get_u8(tb[ETHTOOL_A_PORT_TYPE]);
	print_string(PRINT_ANY, "port_type", "\tPort type: %s\n",
		     port_type_str(port_type));

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

	flags = get_stats_flag(nlctx, ETHTOOL_MSG_PORT_GET, ETHTOOL_A_PORT_HEADER);
	ret = nlsock_prep_filtered_dump_request(nlsk, ETHTOOL_MSG_PORT_GET,
						ETHTOOL_A_PORT_HEADER, flags);
	if (ret)
		return ret;

	new_json_obj(ctx->json);
	ret = nlsock_send_get_request(nlsk, port_reply_cb);
	delete_json_obj();
	return ret;
}
