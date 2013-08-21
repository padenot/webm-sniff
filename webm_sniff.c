#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

/**
* Determine if a file is a webm file.
* Compile with:
*   gcc webm_sniff.c -o webm_sniff
*
* and run with:
*   ./webm_sniff video0.webm video1.webm ...
*/

/* Maximum offset at which we will attempt to sniff, per spec. */
const size_t MAX_SNIFF_OFFSET = 512;

/* Maximum offset at which a doctype can be found, in Matroska. */
const size_t DOCTYPE_MAX_OFFSET = 4 + 8  /* EBML + header size */
                                + 8 + 2  /* EBML Version (up to 8 bytes) */
                                + 8 + 2  /* EBML Read version (up to 8 bytes) */
                                + 1 + 2  /* EBML Max Id Length (4 or less: coded on one byte) */
                                + 1 + 2; /* EBML Max size length (8 or less: coded on one byte) */

const uint8_t WEBM_DOCTYPE[] = {'w', 'e', 'b', 'm'};


void usage(char * name)
{
  printf("Usage: %s webm_file [webm_file...]\n", name);
  exit(0);
}

int parse_vint(uint8_t * buffer, size_t size, uint64_t * rv)
{
  size_t i = 1, number_size;
  uint32_t mask = 1 << 7;
  const size_t vint_max_len = 8;

  *rv = 0;

  while (i  < vint_max_len && i < size) {
    if ((*buffer & mask) != 0) {
      break;
    }
    mask >>= 1;
    i += 1;
  }

  number_size = i;

  *rv = *buffer++ & ~mask;

  while (--i) {
    *rv <<= 8;
    *rv |= *buffer++;
  }

  return number_size;
}

int match_padded_string(const uint8_t * lhs, size_t lhs_size, const uint8_t * rhs, size_t rhs_size)
{
  size_t i;
  size_t min_size = lhs_size < rhs_size ? lhs_size : rhs_size;
  size_t max_size = lhs_size > rhs_size ? lhs_size : rhs_size;
  const uint8_t * max_buf = lhs_size > rhs_size ? lhs : rhs;

  for (i = min_size; i < max_size; i++) {
    if (max_buf[i] != '\0') {
      return 1;
    }
  }

  for (i = 0; i < min_size; i++) {
    if (lhs[i] != rhs[i]) {
      return 1;
    }
  }

  return 0;
}

/* Attempt to determine if a buffer is a webm bitstream.
 * Returns the offset of the doctype in case of success, 0 otherwise. */
int sniff_webm(uint8_t * buffer, size_t size)
{
  uint8_t * iter = buffer;
  uint8_t * end = buffer + size;
  if (size >= 4) {
    /* read the EBML ID */
    if (buffer[0] != 0x1a ||
        buffer[1] != 0x45 ||
        buffer[2] != 0xdf ||
        buffer[3] != 0xa3) {
      return -1;
    }
    while (iter != end && (size_t)(iter - buffer) < (DOCTYPE_MAX_OFFSET - 4)) {
      /* find the ebml id of the doctype. */
      if (iter[0] == 0x42 && iter[1] == 0x82) {
        /* length of the doctype, and number of bytes taken by the size of the
         * string encoded as a vint. */
        uint64_t string_len;
        size_t number_size;
        /* two bytes for the doctype
         * ebml id */
        iter += 2;
        /* get the string size */
        number_size = parse_vint(iter, (size_t)(end - iter), &string_len);
        iter += number_size;

        /* check if we still have room to read the doctype from the buffer. */
        if (iter + 4 < end) {
          /* actually check the doctype. */
          if (match_padded_string(iter, string_len, WEBM_DOCTYPE, sizeof(WEBM_DOCTYPE)) == 0) {
            return iter - buffer;
          }
          return -1;
        }
      }
      iter++;
    }
  }
  return -1;
}

int sniff_webm_file(char * path)
{
  FILE * f;
  uint8_t buffer[MAX_SNIFF_OFFSET];
  int read;
  int doctype_offset;

  f = fopen(path, "r");
  if (!f) {
    fprintf(stderr, "%s: file not found\n", path);
    return 0;
  }

  read = fread(buffer, 1, MAX_SNIFF_OFFSET, f);

  if (read < 0) {
    fprintf(stderr, "read error\n");
  }

  doctype_offset = sniff_webm(buffer, MAX_SNIFF_OFFSET);

  if (doctype_offset > 0) {
    printf("%s is a webm file (doctype at %d).\n", path, doctype_offset);
  } else {
    printf("%s is not a webm file.\n", path);
  }

  fclose(f);

  return 0;
}

void test_match_padded_string()
{
  uint8_t nullstring[] = {0x00};
  uint8_t a[] = {'a'};
  uint8_t a0[] = "a";
  uint8_t a00[] = {'a', 0x00, 0x00};

  uint8_t b[] = {'b'};
  uint8_t b0[] = "b";
  uint8_t b00[] = {'b', 0x00, 0x00};

  uint8_t aa[] = {'a', 'a'};
  uint8_t aa0[] = {'a', 'a', 0x00};
  uint8_t aa00[] = {'a', 'a', 0x00, 0x00};

  uint8_t bb[] = {'b', 'b'};
  uint8_t bb0[] = {'b', 'b', 0x00};
  uint8_t bb00[] = {'b', 'b', 0x00, 0x00};

  /* should match */
  assert(match_padded_string(a, 1, a0, 2) == 0);
  assert(match_padded_string(a0, 2, a, 1) == 0);
  assert(match_padded_string(a, 1, a00, 3) == 0);
  assert(match_padded_string(a00, 3, a, 1) == 0);
  assert(match_padded_string(a0, 2, a00, 3) == 0);
  assert(match_padded_string(a00, 3, a0, 2) == 0);

  assert(match_padded_string(aa, 2, aa0, 3) == 0);
  assert(match_padded_string(aa0, 3, aa, 2) == 0);
  assert(match_padded_string(aa, 2, aa00, 4) == 0);
  assert(match_padded_string(aa00, 4, aa, 2) == 0);
  assert(match_padded_string(aa0, 3, aa00, 4) == 0);
  assert(match_padded_string(aa00, 4, aa0, 3) == 0);

  assert(match_padded_string(a, 1, b0, 2) == 1);
  assert(match_padded_string(a0, 2, b, 1) == 1);
  assert(match_padded_string(a, 1, b00, 3) == 1);
  assert(match_padded_string(a00, 3, b, 1) == 1);
  assert(match_padded_string(a0, 2, b00, 3) == 1);
  assert(match_padded_string(a00, 3, b0, 2) == 1);
  assert(match_padded_string(nullstring, 1, b0, 2) == 1);

  assert(match_padded_string(aa, 2, bb0, 2) == 1);
  assert(match_padded_string(aa0, 3, bb, 1) == 1);
  assert(match_padded_string(aa, 2, bb00, 3) == 1);
  assert(match_padded_string(aa00, 4, bb, 1) == 1);
  assert(match_padded_string(aa0, 3, bb00, 3) == 1);
  assert(match_padded_string(aa00, 4, bb0, 2) == 1);
  assert(match_padded_string(nullstring, 1, bb0, 2) == 1);

  assert(match_padded_string(a, 1, bb0, 2) == 1);
  assert(match_padded_string(a0, 2, bb, 1) == 1);
  assert(match_padded_string(a, 1, bb00, 3) == 1);
  assert(match_padded_string(a00, 3, bb, 1) == 1);
  assert(match_padded_string(a0, 2, bb00, 3) == 1);
  assert(match_padded_string(a00, 3, bb0, 2) == 1);
  assert(match_padded_string(nullstring, 1, bb0, 2) == 1);
}

void test_parse_vint()
{
  uint8_t mask[] = {0x80};
  uint8_t one[] = {0x81};
  /* 0xff means "size unknown" */
  uint8_t maxonebyte[] = {0xfe};
  uint8_t lowtwobytes[] = {0x40, 0x00};
  uint8_t maxtwobytes[] = {0x7f, 0xfe};
  uint64_t out;
  assert(parse_vint(mask, sizeof(mask), &out) == 1 && out == 0);
  assert(parse_vint(one, sizeof(one), &out) == 1 && out == 1);
  assert(parse_vint(maxonebyte, sizeof(maxonebyte), &out) == 1 && out == 126);
  assert(parse_vint(lowtwobytes, sizeof(lowtwobytes), &out) == 2 && out == 0);
  assert(parse_vint(maxtwobytes, sizeof(lowtwobytes), &out) == 2 && out == 16382);
}

int main(int argc, char * argv[])
{
  int i;

  test_match_padded_string();
  test_parse_vint();

  if (argc == 1) {
    usage(argv[0]);
  }

  for (i = 1; i < argc; i++) {
    sniff_webm_file(argv[i]);
  }

  return 0;
}
