#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dstu9212/dstu9212.h>

#define VSL3_HEADER_BYTES 16
#define VSL3_VERSION 1

enum vsl3_type {
	VSL3_PUBLIC_KEY = 1,
	VSL3_SECRET_KEY = 2,
	VSL3_DETACHED_SIGNATURE = 3,
	VSL3_ATTACHED_SIGNATURE = 4
};

enum {
	EXIT_OK = 0,
	EXIT_INVALID = 1,
	EXIT_USAGE = 2
};

struct options {
	const char *command;
	const char *file;
	const char *public_key;
	const char *private_key;
	const char *type;
	const char *signing;
	const char *signature;
	const char *out;
};

struct buffer {
	uint8_t *data;
	size_t len;
};

static void print_help(void)
{
	printf("lab3 - DSTU 9212:2023 file signing utility (mode=%d, %s)\n\n",
		DSTU9212_MODE, dstu9212_mode_name());
	puts("Usage:");
	puts("  lab3 --help");
	puts("  lab3 --command=generate --public-key=<pk.vpk> --private-key=<sk.vsk>");
	puts("  lab3 --command=sign --file=<message> --private-key=<sk.vsk>");
	puts("       --type=detached|attached --signing=deterministic|randomized");
	puts("       --out=<output>");
	puts("  lab3 --command=verify --file=<message> --public-key=<pk.vpk>");
	puts("       --type=detached --signature=<message.vsig>");
	puts("  lab3 --command=verify --file=<message.vsigned> --public-key=<pk.vpk>");
	puts("       --type=attached [--out=<recovered>]");
	puts("");
	puts("Notes:");
	puts("  * output files must not exist yet; they are never overwritten;");
	puts("  * --type=detached writes only the signature (VSL3 type 3);");
	puts("  * --type=attached writes signature + message (VSL3 type 4);");
	puts("  * attached verify extracts the message to --out only if valid.");
	puts("");
	printf("Sizes: public key=%zu, private key=%zu, signature=%zu bytes\n",
		dstu9212_public_key_bytes(), dstu9212_secret_key_bytes(),
		dstu9212_signature_bytes());
	puts("Exit codes: 0 success, 1 invalid signature, 2 usage or I/O error.");
}

static int set_option(const char **slot, const char *name, const char *value)
{
	if (*slot != NULL) {
		fprintf(stderr, "error: option --%s given more than once\n", name);
		return 0;
	}
	if (*value == '\0') {
		fprintf(stderr, "error: option --%s has an empty value\n", name);
		return 0;
	}
	*slot = value;
	return 1;
}

static int parse_options(int argc, char **argv, struct options *opt)
{
	static const struct {
		const char *name;
		size_t offset;
	} known[] = {
		{ "command", offsetof(struct options, command) },
		{ "file", offsetof(struct options, file) },
		{ "public-key", offsetof(struct options, public_key) },
		{ "private-key", offsetof(struct options, private_key) },
		{ "type", offsetof(struct options, type) },
		{ "signing", offsetof(struct options, signing) },
		{ "signature", offsetof(struct options, signature) },
		{ "out", offsetof(struct options, out) },
	};

	memset(opt, 0, sizeof(*opt));
	for (int i = 1; i < argc; i++) {
		const char *arg = argv[i];
		const char *eq;
		size_t name_len;
		size_t k;

		if (strncmp(arg, "--", 2) != 0 || (eq = strchr(arg, '=')) == NULL) {
			fprintf(stderr, "error: unexpected argument '%s' "
				"(expected --name=value)\n", arg);
			return 0;
		}
		arg += 2;
		name_len = (size_t)(eq - arg);
		for (k = 0; k < sizeof(known) / sizeof(known[0]); k++) {
			if (strlen(known[k].name) == name_len &&
			    strncmp(known[k].name, arg, name_len) == 0)
				break;
		}
		if (k == sizeof(known) / sizeof(known[0])) {
			fprintf(stderr, "error: unknown option '%s'\n", argv[i]);
			return 0;
		}
		if (!set_option((const char **)((char *)opt + known[k].offset),
				known[k].name, eq + 1))
			return 0;
	}
	return 1;
}

static int require(const char *value, const char *name)
{
	if (value == NULL) {
		fprintf(stderr, "error: option --%s is required\n", name);
		return 0;
	}
	return 1;
}

static int forbid(const char *value, const char *name, const char *command)
{
	if (value != NULL) {
		fprintf(stderr, "error: option --%s is not used by --command=%s\n",
			name, command);
		return 0;
	}
	return 1;
}

static int file_exists(const char *path)
{
	FILE *f = fopen(path, "rb");

	if (f == NULL)
		return 0;
	fclose(f);
	return 1;
}

static int read_file(const char *path, struct buffer *out)
{
	FILE *f = fopen(path, "rb");
	uint8_t *data = NULL;
	size_t len = 0;
	size_t cap = 0;

	out->data = NULL;
	out->len = 0;
	if (f == NULL) {
		fprintf(stderr, "error: cannot open '%s': %s\n", path, strerror(errno));
		return 0;
	}
	for (;;) {
		size_t n;

		if (len == cap) {
			size_t new_cap = cap == 0 ? 4096 : cap * 2;
			uint8_t *tmp;

			if (new_cap < cap) {
				fprintf(stderr, "error: '%s' is too large\n", path);
				goto fail;
			}
			tmp = realloc(data, new_cap);
			if (tmp == NULL) {
				fprintf(stderr, "error: out of memory reading '%s'\n", path);
				goto fail;
			}
			data = tmp;
			cap = new_cap;
		}
		n = fread(data + len, 1, cap - len, f);
		len += n;
		if (n == 0) {
			if (ferror(f)) {
				fprintf(stderr, "error: cannot read '%s'\n", path);
				goto fail;
			}
			break;
		}
	}
	fclose(f);
	out->data = data;
	out->len = len;
	return 1;

fail:
	if (data != NULL) {
		dstu9212_secure_zero(data, cap);
		free(data);
	}
	fclose(f);
	return 0;
}

static void free_buffer(struct buffer *b)
{
	if (b->data != NULL) {
		dstu9212_secure_zero(b->data, b->len);
		free(b->data);
	}
	b->data = NULL;
	b->len = 0;
}

static void store_le64(uint8_t *p, uint64_t v)
{
	for (int i = 0; i < 8; i++)
		p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t load_le64(const uint8_t *p)
{
	uint64_t v = 0;

	for (int i = 7; i >= 0; i--)
		v = (v << 8) | p[i];
	return v;
}

static int write_vsl3(const char *path, uint8_t type,
	const uint8_t *p1, size_t n1,
	const uint8_t *p2, size_t n2,
	const uint8_t *p3, size_t n3)
{
	uint8_t header[VSL3_HEADER_BYTES] = { 0x56, 0x53, 0x4C, 0x33 };
	FILE *f;
	int ok;

	if (file_exists(path)) {
		fprintf(stderr, "error: '%s' already exists, refusing to overwrite\n",
			path);
		return 0;
	}
	header[4] = VSL3_VERSION;
	header[5] = (uint8_t)DSTU9212_MODE;
	header[6] = type;
	header[7] = 0;
	store_le64(header + 8, (uint64_t)n1 + n2 + n3);

	f = fopen(path, "wb");
	if (f == NULL) {
		fprintf(stderr, "error: cannot create '%s': %s\n", path, strerror(errno));
		return 0;
	}
	ok = fwrite(header, 1, sizeof(header), f) == sizeof(header) &&
	     (n1 == 0 || fwrite(p1, 1, n1, f) == n1) &&
	     (n2 == 0 || fwrite(p2, 1, n2, f) == n2) &&
	     (n3 == 0 || fwrite(p3, 1, n3, f) == n3);
	if (fclose(f) != 0)
		ok = 0;
	if (!ok) {
		fprintf(stderr, "error: cannot write '%s'\n", path);
		remove(path);
		return 0;
	}
	return 1;
}

static int write_raw(const char *path, const uint8_t *data, size_t len)
{
	FILE *f;
	int ok;

	if (file_exists(path)) {
		fprintf(stderr, "error: '%s' already exists, refusing to overwrite\n",
			path);
		return 0;
	}
	f = fopen(path, "wb");
	if (f == NULL) {
		fprintf(stderr, "error: cannot create '%s': %s\n", path, strerror(errno));
		return 0;
	}
	ok = len == 0 || fwrite(data, 1, len, f) == len;
	if (fclose(f) != 0)
		ok = 0;
	if (!ok) {
		fprintf(stderr, "error: cannot write '%s'\n", path);
		remove(path);
	}
	return ok;
}

static const char *type_name(uint8_t type)
{
	switch (type) {
	case VSL3_PUBLIC_KEY: return "public key";
	case VSL3_SECRET_KEY: return "private key";
	case VSL3_DETACHED_SIGNATURE: return "detached signature";
	case VSL3_ATTACHED_SIGNATURE: return "attached signature";
	default: return "unknown object";
	}
}

static int read_vsl3(const char *path, uint8_t expected_type,
	size_t expected_len, struct buffer *file,
	const uint8_t **payload, size_t *payload_len)
{
	const uint8_t *h;
	uint64_t len;

	if (!read_file(path, file))
		return 0;
	h = file->data;
	if (file->len < VSL3_HEADER_BYTES ||
	    h[0] != 0x56 || h[1] != 0x53 || h[2] != 0x4C || h[3] != 0x33) {
		fprintf(stderr, "error: '%s' is not a VSL3 container\n", path);
		goto fail;
	}
	if (h[4] != VSL3_VERSION) {
		fprintf(stderr, "error: '%s': unsupported VSL3 version %u\n",
			path, h[4]);
		goto fail;
	}
	if (h[5] != DSTU9212_MODE) {
		fprintf(stderr, "error: '%s' uses parameter set %u, "
			"but this build is mode %d\n", path, h[5], DSTU9212_MODE);
		goto fail;
	}
	if (h[6] != expected_type) {
		fprintf(stderr, "error: '%s' contains a %s, expected a %s\n",
			path, type_name(h[6]), type_name(expected_type));
		goto fail;
	}
	if (h[7] != 0) {
		fprintf(stderr, "error: '%s': reserved header byte is not 0\n", path);
		goto fail;
	}
	len = load_le64(h + 8);
	if (len != (uint64_t)(file->len - VSL3_HEADER_BYTES)) {
		fprintf(stderr, "error: '%s': header says %llu payload bytes, "
			"file has %zu\n", path, (unsigned long long)len,
			file->len - VSL3_HEADER_BYTES);
		goto fail;
	}
	if (expected_len != 0 && len != expected_len) {
		fprintf(stderr, "error: '%s': %s must be %zu bytes, got %llu\n",
			path, type_name(expected_type), expected_len,
			(unsigned long long)len);
		goto fail;
	}
	*payload = h + VSL3_HEADER_BYTES;
	*payload_len = (size_t)len;
	return 1;

fail:
	free_buffer(file);
	return 0;
}

static int cmd_generate(const struct options *opt)
{
	uint8_t pk[DSTU9212_API_PUBLIC_KEY_BYTES];
	uint8_t sk[DSTU9212_API_SECRET_KEY_BYTES];
	int rc = EXIT_USAGE;

	if (!require(opt->public_key, "public-key") ||
	    !require(opt->private_key, "private-key") ||
	    !forbid(opt->file, "file", "generate") ||
	    !forbid(opt->type, "type", "generate") ||
	    !forbid(opt->signing, "signing", "generate") ||
	    !forbid(opt->signature, "signature", "generate") ||
	    !forbid(opt->out, "out", "generate"))
		return EXIT_USAGE;
	if (strcmp(opt->public_key, opt->private_key) == 0) {
		fputs("error: public and private key paths must differ\n", stderr);
		return EXIT_USAGE;
	}
	// Check both up front so that we never leave a half-written key pair.
	if (file_exists(opt->public_key) || file_exists(opt->private_key)) {
		fprintf(stderr, "error: '%s' already exists, refusing to overwrite\n",
			file_exists(opt->public_key) ? opt->public_key : opt->private_key);
		return EXIT_USAGE;
	}

	if (dstu9212_keygen(pk, sk) != DSTU9212_OK) {
		fputs("error: key generation failed\n", stderr);
		goto out;
	}
	if (!write_vsl3(opt->private_key, VSL3_SECRET_KEY,
			sk, sizeof(sk), NULL, 0, NULL, 0))
		goto out;
	if (!write_vsl3(opt->public_key, VSL3_PUBLIC_KEY,
			pk, sizeof(pk), NULL, 0, NULL, 0)) {
		remove(opt->private_key);
		goto out;
	}
	printf("generated key pair (mode %d)\n", DSTU9212_MODE);
	printf("  public key : %s (%zu bytes payload)\n", opt->public_key, sizeof(pk));
	printf("  private key: %s (%zu bytes payload)\n", opt->private_key, sizeof(sk));
	rc = EXIT_OK;

out:
	dstu9212_secure_zero(sk, sizeof(sk));
	return rc;
}

static int cmd_sign(const struct options *opt)
{
	struct buffer msg = { 0 };
	struct buffer sk_file = { 0 };
	const uint8_t *sk;
	size_t sk_len;
	uint8_t sig[DSTU9212_API_SIGNATURE_BYTES];
	size_t sig_len = 0;
	int attached;
	int randomized;
	dstu9212_status st;
	int rc = EXIT_USAGE;

	if (!require(opt->file, "file") ||
	    !require(opt->private_key, "private-key") ||
	    !require(opt->type, "type") ||
	    !require(opt->signing, "signing") ||
	    !require(opt->out, "out") ||
	    !forbid(opt->public_key, "public-key", "sign") ||
	    !forbid(opt->signature, "signature", "sign"))
		return EXIT_USAGE;

	if (strcmp(opt->type, "attached") == 0) {
		attached = 1;
	} else if (strcmp(opt->type, "detached") == 0) {
		attached = 0;
	} else {
		fprintf(stderr, "error: --type must be attached or detached, "
			"got '%s'\n", opt->type);
		return EXIT_USAGE;
	}
	if (strcmp(opt->signing, "randomized") == 0) {
		randomized = 1;
	} else if (strcmp(opt->signing, "deterministic") == 0) {
		randomized = 0;
	} else {
		fprintf(stderr, "error: --signing must be deterministic or "
			"randomized, got '%s'\n", opt->signing);
		return EXIT_USAGE;
	}
	if (file_exists(opt->out)) {
		fprintf(stderr, "error: '%s' already exists, refusing to overwrite\n",
			opt->out);
		return EXIT_USAGE;
	}

	if (!read_vsl3(opt->private_key, VSL3_SECRET_KEY,
			dstu9212_secret_key_bytes(), &sk_file, &sk, &sk_len))
		goto out;
	if (!read_file(opt->file, &msg))
		goto out;

	if (randomized)
		st = dstu9212_sign_randomized(sig, sizeof(sig), &sig_len,
			sk, sk_len, msg.data, msg.len);
	else
		st = dstu9212_sign_deterministic(sig, sizeof(sig), &sig_len,
			sk, sk_len, msg.data, msg.len);
	free_buffer(&sk_file);
	if (st != DSTU9212_OK) {
		fputs("error: signing failed\n", stderr);
		goto out;
	}

	if (attached) {
		uint8_t len_field[8];

		store_le64(len_field, sig_len);
		if (!write_vsl3(opt->out, VSL3_ATTACHED_SIGNATURE,
				len_field, sizeof(len_field), sig, sig_len,
				msg.data, msg.len))
			goto out;
	} else {
		if (!write_vsl3(opt->out, VSL3_DETACHED_SIGNATURE,
				sig, sig_len, NULL, 0, NULL, 0))
			goto out;
	}
	printf("signed '%s' (%zu bytes), %s %s signature -> '%s' "
		"(signature %zu bytes)\n", opt->file, msg.len,
		randomized ? "randomized" : "deterministic",
		attached ? "attached" : "detached", opt->out, sig_len);
	rc = EXIT_OK;

out:
	free_buffer(&sk_file);
	free_buffer(&msg);
	return rc;
}

static int cmd_verify(const struct options *opt)
{
	struct buffer pk_file = { 0 };
	struct buffer msg_file = { 0 };
	struct buffer sig_file = { 0 };
	const uint8_t *pk;
	size_t pk_len;
	const uint8_t *msg;
	size_t msg_len;
	const uint8_t *sig;
	size_t sig_len;
	int attached;
	int rc = EXIT_USAGE;

	if (!require(opt->file, "file") ||
	    !require(opt->public_key, "public-key") ||
	    !require(opt->type, "type") ||
	    !forbid(opt->private_key, "private-key", "verify") ||
	    !forbid(opt->signing, "signing", "verify"))
		return EXIT_USAGE;

	if (strcmp(opt->type, "attached") == 0) {
		attached = 1;
		if (!forbid(opt->signature, "signature", "verify --type=attached"))
			return EXIT_USAGE;
		if (opt->out != NULL && file_exists(opt->out)) {
			fprintf(stderr, "error: '%s' already exists, refusing to "
				"overwrite\n", opt->out);
			return EXIT_USAGE;
		}
	} else if (strcmp(opt->type, "detached") == 0) {
		attached = 0;
		if (!require(opt->signature, "signature") ||
		    !forbid(opt->out, "out", "verify --type=detached"))
			return EXIT_USAGE;
	} else {
		fprintf(stderr, "error: --type must be attached or detached, "
			"got '%s'\n", opt->type);
		return EXIT_USAGE;
	}

	if (!read_vsl3(opt->public_key, VSL3_PUBLIC_KEY,
			dstu9212_public_key_bytes(), &pk_file, &pk, &pk_len))
		goto out;

	if (attached) {
		const uint8_t *payload;
		size_t payload_len;
		uint64_t n;

		if (!read_vsl3(opt->file, VSL3_ATTACHED_SIGNATURE, 0,
				&msg_file, &payload, &payload_len))
			goto out;
		if (payload_len < 8) {
			fprintf(stderr, "error: '%s': attached payload is truncated\n",
				opt->file);
			goto out;
		}
		n = load_le64(payload);
		if (n > payload_len - 8) {
			fprintf(stderr, "error: '%s': signature length %llu exceeds "
				"payload\n", opt->file, (unsigned long long)n);
			goto out;
		}
		sig = payload + 8;
		sig_len = (size_t)n;
		msg = sig + sig_len;
		msg_len = payload_len - 8 - sig_len;
	} else {
		if (!read_vsl3(opt->signature, VSL3_DETACHED_SIGNATURE, 0,
				&sig_file, &sig, &sig_len))
			goto out;
		if (!read_file(opt->file, &msg_file))
			goto out;
		msg = msg_file.data;
		msg_len = msg_file.len;
	}

	if (dstu9212_verify_signature(pk, pk_len, sig, sig_len,
			msg, msg_len) != DSTU9212_OK) {
		printf("INVALID: signature of '%s' does not verify\n", opt->file);
		rc = EXIT_INVALID;
		goto out;
	}
	printf("VALID: signature of '%s' is correct (%s, message %zu bytes)\n",
		opt->file, attached ? "attached" : "detached", msg_len);

	if (attached && opt->out != NULL) {
		if (!write_raw(opt->out, msg, msg_len))
			goto out;
		printf("recovered message written to '%s'\n", opt->out);
	}
	rc = EXIT_OK;

out:
	free_buffer(&pk_file);
	free_buffer(&msg_file);
	free_buffer(&sig_file);
	return rc;
}

int main(int argc, char **argv)
{
	struct options opt;

	if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
		print_help();
		return argc == 1 ? EXIT_USAGE : EXIT_OK;
	}
	if (!parse_options(argc, argv, &opt))
		goto usage;
	if (!require(opt.command, "command"))
		goto usage;

	if (strcmp(opt.command, "generate") == 0)
		return cmd_generate(&opt);
	if (strcmp(opt.command, "sign") == 0)
		return cmd_sign(&opt);
	if (strcmp(opt.command, "verify") == 0)
		return cmd_verify(&opt);
	fprintf(stderr, "error: unknown command '%s'\n", opt.command);

usage:
	fputs("run 'lab3 --help' for usage\n", stderr);
	return EXIT_USAGE;
}
