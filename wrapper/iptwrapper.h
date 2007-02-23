/*
 * iptables wrapper
 */

/* System headers */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* Include autotools' config.h if provided */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

/* Main function */
int main(int argc, char *argv[])
{
    /* Variables */
    static const char *ok_targets[] = {
	/* Standard built-in targets */
	"ACCEPT", "DROP", "QUEUE", "RETURN",

	/* Extensions */
	"BALANCE", "CLASSIFY", "CLUSTERIP", "CONNMARK", "DNAT", "DSCP", "ECN",
	"HL", "IPMARK", "IPV4OPTSSTRIP", "LOG", "MARK", "MASQUERADE", "MIRROR",
	"NETMAP", "NFQUEUE", "NOTRACK", "REDIRECT", "REJECT", "ROUTE", "SAME",
	"SET", "SNAT", "TARPIT", "TCPMSS", "TOS", "TRACE", "TTL", "ULOG", "XOR",

	/* ebtables extensions */
	"arpreply", "dnat", "mark", "redirect", "snat"
    };
    static const char prefix[] = TABLES_PREFIX;
    const int prefix_len = strlen(prefix);

    int arg = 1, num = 0, end, do_prefix, i;
    size_t j;
    char *table;

    /* Check argument count */
    if (argc < arg + 1)
	return EXIT_FAILURE;

    /* Set the executable path */
    argv[0] = IPTABLES_PATH;

    /* If the first argument is "t", skip the two first ones */
    if (strcmp(argv[arg], "-t") == 0) {
	arg += 2;
	if (argc < arg + 1)
	    return EXIT_FAILURE;
    }

    if (argv[arg][0] == '-' && argv[arg][1] != '\0' && argv[arg][2] == '\0') {
	/* Compute the number of arguments to prefix */
	switch (argv[arg][1]) {
	case 'A':
	case 'D':
	case 'I':
	case 'N':
	case 'P':
	case 'R':
	    num = 1;
	    break;

	case 'F':
	case 'L':
	case 'X':
	case 'Z':
	    if (arg + 1 < argc && argv[arg + 1][0] != '-')
		num = 1;
	    break;

	case 'E':
	    num = 2;
	}

	/* The last argument to prefix */
	if ((end = arg + num) >= argc)
	    end = argc - 1;

	/* Prefix some arguments */
	for (i = arg + 1; i < argc; i++) {
	    if (i > end + 1 && strcmp(argv[i - 1], "-j") == 0) {
		do_prefix = 1;
		for (j = 0; j < sizeof(ok_targets) / sizeof(*ok_targets); j++)
		    if (strcmp(ok_targets[j], argv[i]) == 0) {
			do_prefix = 0;
			break;
		    }
	    } else
		do_prefix = 0;

	    if (i <= end || do_prefix) {
		table = (char *)malloc(strlen(argv[i]) + prefix_len + 1);
		if (table == (char *)0) {
		    perror("malloc");
		    return errno;
		}

		sprintf(table, "%s%s", prefix, argv[i]);
		argv[i] = table;
	    }
	}
    }

    /* Execute iptables */
    execv(argv[0], argv);
    return EXIT_FAILURE;
}
