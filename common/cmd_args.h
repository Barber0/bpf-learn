#ifndef __COMMON_CMD_ARGS_H
#define __COMMON_CMD_ARGS_H

#include <stdio.h>
#include <getopt.h>
#include <stdbool.h>

#include "common_define.h"

struct option_wrapper
{
    struct option option;
    char *help;
    char *metavar;
    bool required;
};

void parse_cmd_args(
    int argc,
    char **argv,
    const struct option_wrapper *wrappers,
    struct config *cfg);

#endif