#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

static void die(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

static char *slurp(const char *fn, size_t *lenp)
{
    size_t len = 0;
    char *buf = 0;
    int l;
    FILE *fp;

    if ((fp = fopen(fn, "r")) == 0) {
	perror(fn);
	exit(1);
    }
    while (1) {
	buf = realloc(buf, len + 65536);
	if (!buf)
	    abort();
	l = fread(buf + len, 1, 65536, fp);
	if (l < 0) {
	    perror("fread");
	    exit(1);
	}
	if (l == 0)
	    break;
	len += l;
    }
    fclose(fp);
    buf = realloc(buf, len + 1);
    if (!buf)
	abort();
    buf[len] = 0;
    if (lenp)
	*lenp = len;
    return buf;
}

void
do_run(char **args, char **out_p, size_t *outl_p)
{
    int fds[2];
    pid_t pid;
    char *out = NULL;
    size_t outl = 0;
    ssize_t l;
    int status;

    if (pipe(fds)) {
	perror("pipe");
	exit(1);
    }
    pid = fork();
    if (pid == (pid_t)-1) {
	perror("fork");
	exit(1);
    }
    if (pid == 0) {
	close(fds[0]);
	if (fds[1] != 1) {
	    if (dup2(fds[1], 1) == -1) {
		perror("dup2");
		exit(1);
	    }
	}
	close(2);
	if (dup2(1, 2) == -1) {
	    perror("dup2");
	    exit(1);
	}
	execvp(args[0], args);
	perror(args[0]);
	_exit(1);
    }
    close(fds[1]);
    for (;;) {
        out = realloc(out, outl + 1024);
	l = read(fds[0], out + outl, 1024);
	if (l == 0)
	    break;
	if (l < 0) {
	    if (errno == EINTR)
		continue;
	    perror("read");
	    exit(1);
	}
	outl += l;
    }
    close(fds[0]);
    for (;;) {
        pid_t p = waitpid(pid, &status, 0);
	if (p == (pid_t)-1) {
	    if (errno == EINTR)
		continue;
	    perror("waitpid");
	    exit(1);
	}
	if (p != pid) {
	    fprintf(stderr, "weird pid returned by waitpid\n");
	    exit(1);
	}
	break;
    }
    if (outl && out[outl - 1] != '\n') {
        out = realloc(out, outl + 8);
	memcpy(out + outl, "[noeof]\n", 8);
	outl += 8;
    }
    if (status != 0) {
	char exitline[256];
	size_t exitlinelen;
	sprintf(exitline, "Exit status: %d\n", WIFEXITED(status) ? WEXITSTATUS(status) : status);
	exitlinelen = strlen(exitline);
        out = realloc(out, outl + exitlinelen);
	memmove(out + exitlinelen, out, outl);
	memcpy(out, exitline, exitlinelen);
	outl += exitlinelen;
    }
    *out_p = out;
    *outl_p = outl;
}

static inline size_t
linelen(char *o, size_t l)
{
    void *p = memchr(o, '\n', l);
    return p ? (char *)p - o + 1: l;
}

int
do_diff(char *out, size_t outl, char *exp, size_t expl)
{
    int hasdiff = 0;
    size_t ol, el, nol, nel;

    while (outl || expl) {
	ol = linelen(out, outl);
	el = linelen(exp, expl);
	if (ol == el && memcmp(out, exp, ol) == 0) {
	    out += ol;
	    exp += el;
	    outl -= ol;
	    expl -= el;
	    continue;
	}
	hasdiff = 1;
	nol = linelen(out + ol, outl - ol);
	nel = linelen(exp + el, expl - el);
	if (el == nol && memcmp(exp, out + ol, el) == 0) {
	    printf("+%.*s", (int)ol, out);
	    out += ol;
	    outl -= ol;
	    continue;
	}
	if (ol == nel && memcmp(out, exp + el, ol) == 0) {
	    printf("-%.*s", (int)el, exp);
	    exp += el;
	    expl -= el;
	    continue;
	}
	if (el) {
	    printf("-%.*s", (int)el, exp);
	    exp += el;
	    expl -= el;
	} else {
	    printf("+%.*s", (int)ol, out);
	    out += ol;
	    outl -= ol;
	}
    }
    return hasdiff;
}

void
add_skip(char *what, char **skipp)
{
    size_t whatl = strlen(what);
    char *s;
    s = *skipp;
    while (s && *s) {
	if (!strncmp(s, what, whatl))
	    return;	/* already in skip */
	s = strchr(s, ',');
	if (s && *s == ' ')
	    s++;
    }
    if (!*skipp)
	*skipp = strdup(what);
    else {
	size_t oldlen = strlen(*skipp);
	*skipp = realloc(*skipp, oldlen + 2 + whatl + 1);
	strcpy(*skipp + oldlen, ", ");
	strcpy(*skipp + oldlen + 2, what);
    }
}

int main(int argc, char **argv)
{
    char *testcase = NULL;
    char *line, *nextline, *p, *cmd;
    char *testpgpr;
    size_t cmdlen;
    int succeeded = 0, failed = 0, skipped = 0;
    char *skip = NULL, *allskip = NULL;
    int skip_rc = 0;

    p = strrchr(argv[0], '/');
    if (p) {
	testpgpr = malloc(p - argv[0] + 8 + 2);
	memcpy(testpgpr, argv[0], p - argv[0] + 1);
	memcpy(testpgpr + (p - argv[0] + 1), "testpgpr", 8 + 1);
    } else
	testpgpr = strdup("testpgpr");

    if (argc > 3 && !strcmp(argv[1], "--skip-return-code")) {
	skip_rc = atoi(argv[2]);
	argc -= 2;
	argv += 2;
    }
    if (argc != 2)
	die("Usage: runtest [--skip-return-code <rc>] <test.t>");

    testcase = slurp(argv[1], NULL);
    for (line = testcase; *line; line = nextline) {
	if ((p = strchr(line, '\n')) != 0) {
	    *p++ = 0;
	    nextline = p;
	} else {
	    nextline = line + strlen(line);
	}
	while (*line == ' ' || *line == '\t')
	    line++;
	if (!*line || *line == '#')
	    continue;
	cmd = line;
	while (*line && *line != ' ' && *line != '\t')
	    line++;
	cmdlen = line - cmd;
	if (cmdlen == 4 && strncmp(cmd, "TEST", 4) == 0) {
	    cmd += cmdlen;
	    while (*cmd == ' ' || *cmd == '\t')
		cmd++;
	    printf("Testing %s\n", cmd);
	} if ((cmdlen == 7 && strncmp(cmd, "REQUIRE", 7) == 0) || (cmdlen == 10 && strncmp(cmd, "ALLREQUIRE", 10) == 0)) {
	    int isall = cmdlen == 10 ? 1 : 0;
	    char *what;
	    char *out = 0;
	    size_t outl = 0;
	    char *args[4];

	    cmd += cmdlen;
	    while (*cmd == ' ' || *cmd == '\t')
		cmd++;
	    what = cmd;
	    while (*cmd && *cmd != ' ' && *cmd != '\t')
		cmd++;
	    if (*cmd) {
		*cmd++ = 0;
		while (*cmd == ' ' || *cmd == '\t')
		    cmd++;
		if (*cmd) {
		    fprintf(stderr, "REQUIRE/ALLREQUIRE can only handle one arg\n");
		    exit(1);
		}
	    }
	    args[0] = testpgpr;
	    args[1] = "feature";
	    args[2] = what;
	    args[3] = NULL;
	    do_run(args, &out, &outl);
	    if (outl == 0)
		die("bad result from feature check");
	    out[outl - 1] = 0;
	    if (!strncmp(out, "OK", 2))
		continue;
	    if (!strncmp(out, "FAIL", 4))
		add_skip(what, isall ? &allskip :  &skip);
	    else if (strncmp(out, "OK", 2) != 0) {
		fprintf(stderr, "feature check error: %s\n", out);
		exit(1);
	    }
	} else if (cmdlen == 3 && strncmp(cmd, "RUN", 3) == 0) {
	    char *saveptr = NULL;
	    char *arg;
	    char *args[20];
	    int nargs = 0;
	    char *out = 0;
	    size_t outl = 0;
	    char *exp = 0;
	    size_t expl = 0;

	    if (skip || allskip) {
		printf("(skipped: %s)\n", allskip ? allskip : skip);
		skipped++;
		if (skip) {
		    free(skip);
		    skip = 0;
		}
		continue;
	    }
	    args[nargs++] = strdup(testpgpr);
	    cmd += cmdlen;
	    while (*cmd == ' ' || *cmd == '\t')
		cmd++;
	    while ((arg = strtok_r(cmd, " \t", &saveptr)) != NULL) {
		if (nargs == 18)
		    die("too many args to RUN");
		args[nargs++] = strdup(arg);
		cmd = NULL;
	    }
	    args[nargs] = 0;
	    do_run(args, &out, &outl);
	    if (strncmp(nextline, "---\n", 4) == 0) {
		exp = nextline + 4;
		nextline += 4;
		while (*nextline) {
		    if (strncmp(nextline, "---\n", 4) == 0)
			break;
		    if ((p = strchr(nextline, '\n')) != 0) {
			nextline = p + 1;
		    } else {
			nextline += strlen(nextline);
		    }
		}
		expl = nextline - exp;
		if (*nextline)
		    nextline += 4;	/* the ---\n above */
	    }
	    if (do_diff(out, outl, exp, expl))
		failed++;
	    else
		succeeded++;
	    free(out);
	    while (nargs > 0)
		free(args[--nargs]);
	}
    }
    free(skip);
    free(allskip);
    free(testcase);
    free(testpgpr);
    printf("succeeded: %d, failed: %d, skipped: %d\n", succeeded, failed, skipped);
    return failed ? 1 : (skipped && !succeeded) ? skip_rc : 0;
}
