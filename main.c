#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <limits.h>
#include <assert.h>
#include <math.h>

///////////////////////////////////////////////////////////////////////////////

/* LSB - least significant bit */

// sudo apt install wavbreaker
// wavinfo basic.wav

/* Naive Example */

// gcc main.c
// gcc main.c -lm
// -std=c2x
// -std=gnu11
// ./a.out

///////////////////////////////////////////////////////////////////////////////

/*
#define SSIZE_MAX (SIZE_MAX / 2)
*/

/*
#ifdef __clang__
    #define typeof(x) __typeof__(x)
#else
    #define typeof(x) __typeof(x)
#endif
*/

///////////////////////////////////////////////////////////////////////////////

static inline void print_hexdump(const void* data, size_t size)
{
	char ascii[17] = {};
	size_t i, j;
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' '
			&& ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

static inline void print_u8bits(const uint8_t val)
{
	unsigned mask = 0;
	unsigned bit = 0;
	unsigned num = 0;

	for (int i = 7; i >= 0; --i) {
		unsigned num = (unsigned)i;
		mask = 1 << i;
		bit = (val & mask) >> i;
		if (i == 3) {
			printf(" ");
		}
		printf("%u", bit);
	}
	printf("\n");

	return;
}

///////////////////////////////////////////////////////////////////////////////

#define SHOULD_BE_ZERO(x)			\
	do {					\
		typeof(x) _tmp_res_ = (x);	\
		if (_tmp_res_) {		\
			exit(-1);		\
		}				\
	} while (0)

static inline void _closep_(int *fd)
{
	if (*fd >= 0) {
		SHOULD_BE_ZERO(close(*fd));
	}
}

static inline void _freep_(void *p)
{
	void **tmp = (void **)p;
	free(*tmp);
	*tmp = NULL;
}

#define _cleanup_(x) __attribute__((cleanup(x)))
#define _cleanup_close_ _cleanup_(_closep_)
#define _cleanup_free_ _cleanup_(_freep_)

///////////////////////////////////////////////////////////////////////////////

#define MASK(x) ((unsigned char)(1u << (x)))

static inline void set_bit(unsigned char *val, unsigned char id)
{
    // for several: mask(x) | mask (y)
    
    *val |= MASK(id);
    return;
}

static inline void clear_bit(unsigned char *val, unsigned char id)
{
    *val &= ~MASK(id);
    return;
}

static inline void invert_bit(unsigned char *val, unsigned char id)
{
    *val ^= MASK(id);
    return;
}

static inline bool is_bit_1(unsigned char *val, unsigned char id)
{
    if (*val & MASK(id)) {
        return true;
    }
    return false;
}

static inline unsigned char get_bit(unsigned char val, unsigned char id)
{
	return (val & MASK(id)) >> id;
}

///////////////////////////////////////////////////////////////////////////////

// Example
/*
	WaveHeader Size:		12
	ChunkHeader Size:		8
	FormatChunk Size:		16
	RIFF ID:			RIFF
	Total Size:			1048550
	Wave ID:			WAVE
	Chunk ID:			fmt 
	Chunk Size:			16
	Compression format is of type:	1
	Channels:			2
	Sample Rate:			44100
	Bytes / Sec:			176400
	wBlockAlign:			4
	Bits Per Sample Point:		16
	wavDataPtr: 			44
	wavDataSize: 			1048376
*/

/*
[Master RIFF chunk]
   FileTypeBlocID  (4 bytes) : Identifier « RIFF »  (0x52, 0x49, 0x46, 0x46)
   FileSize        (4 bytes) : Overall file size minus 8 bytes
   FileFormatID    (4 bytes) : Format = « WAVE »  (0x57, 0x41, 0x56, 0x45)

[Chunk describing the data format]
   FormatBlocID    (4 bytes) : Identifier « fmt␣ »  (0x66, 0x6D, 0x74, 0x20)
   BlocSize        (4 bytes) : Chunk size minus 8 bytes, which is 16 bytes here  (0x10)
   AudioFormat     (2 bytes) : Audio format (1: PCM integer, 3: IEEE 754 float)
   NbrChannels     (2 bytes) : Number of channels
   Frequency       (4 bytes) : Sample rate (in hertz)
   BytePerSec      (4 bytes) : Number of bytes to read per second (Frequency * BytePerBloc).
   BytePerBloc     (2 bytes) : Number of bytes per block (NbrChannels * BitsPerSample / 8).
   BitsPerSample   (2 bytes) : Number of bits per sample

[Chunk containing the sampled data]
   DataBlocID      (4 bytes) : Identifier « data »  (0x64, 0x61, 0x74, 0x61)
   DataSize        (4 bytes) : SampledData size
   SampledData
*/

typedef struct {
	// Master RIFF chunk
	uint8_t FileTypeBlocID[4];
	uint32_t FileSize;
	uint8_t FileFormatID[4];

	// Chunk describing the data format
	uint8_t FormatBlocID[4];
	uint32_t BlocSize;
	uint16_t AudioFormat;
	uint16_t NbrChannels;
	uint32_t Frequency;
	uint32_t BytePerSec;
	uint16_t BytePerBloc;
	uint16_t BitsPerSample;

	// Chunk containing the sampled data
	uint8_t DataBlocID[4];
	uint32_t DataSize;
} WaveHeader_t;

typedef struct {
	// Wave header
	WaveHeader_t header;

	// Waste data
	uint8_t _waste0[16];
	// Hidden data size
	uint16_t hidden_data_size;
	// Waste data
	uint8_t _waste1[16];
} StegoWave_t;

///////////////////////////////////////////////////////////////////////////////

#define BUILD_BUG_ON_WITH_ZERO(condition) sizeof(struct { unsigned long :-!!(condition); })

#define CONTAINER_BYTE_INC (4)
#define LSB_VAL (0)

static inline int get_min_container_size(size_t data_sz, size_t *resulted_sz)
{
	//_Static_assert(8 == CHAR_BIT, "Bad size of byte");
	//static_assert(8 == CHAR_BIT, "Bad size of byte");
	BUILD_BUG_ON_WITH_ZERO(!(8 == CHAR_BIT));

	size_t tmp = 0;
	if (resulted_sz == NULL) {
		return -1;
	}

	// 1 bit per byte
	if (__builtin_mul_overflow(data_sz, CHAR_BIT, &tmp)) {
        	return -1;
    	}
    	// each 4th byte used
	if (__builtin_mul_overflow(tmp, CONTAINER_BYTE_INC, &tmp)) {
        	return -1;
    	}
    	// + header + wasted data
	if (__builtin_add_overflow(tmp, sizeof(StegoWave_t), &tmp)) {
        	return -1;
    	}

	*resulted_sz = tmp;
	return 0;
}

static inline int open_file(
	const char *const file, int *fd, size_t *sz, bool is_create)
{
	if (file == NULL || fd == NULL || sz == NULL) {
		return -1;
	}

	int file_fd = -1;
	if (is_create) {
		file_fd = open(
			file,
			O_RDWR | O_CREAT | O_TRUNC | O_SYNC,
			S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
	} else {
		file_fd = open(file, O_RDONLY);
	}
	if (file_fd == -1) {
		perror("\t\t Got error");
		return -1;
	}
	printf("\t\t file %s opened\n", file);

/*
	struct stat st = {};
	(void)stat(filename2, &st);
	sz = (unsigned long)st.st_size;
*/
	off_t file_sz = lseek(file_fd, 0L, SEEK_END);
	printf("\t\t lseek() returned: %ld\n", file_sz);
	lseek(file_fd, 0L, SEEK_SET);
	if ((is_create && file_sz < 0 )
		|| (!is_create && file_sz <= 0)
		|| (size_t)file_sz > SSIZE_MAX) {
		(void)close(file_fd);
		return -1;
	}
	--file_sz;
	printf("\t\t file_sz: %ld\n", file_sz);

	*fd = file_fd;
	*sz = (size_t)file_sz;
	return 0;
}

static inline int read_file(const int fd, uint8_t *read_buf, const size_t sz)
{
	if (read_buf == NULL || fd <= 0 || sz == 0) {
		return -1;
	}

	uint8_t *buf = read_buf;
	ssize_t len = (ssize_t)sz;
	ssize_t ret = -1;
	while (len != 0 && (ret = read(fd, buf, len)) != (ssize_t)sz) {
		if (ret == -1) {
			perror("\t\tGot error");
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		len -= ret;
		buf += ret;
		printf("\t\tError: Not full len read\n");
	}
	//for (ssize_t i = 0; i < (ssize_t)data_sz; ++i) printf("%c\n", data_buf[i]);

	return 0;
}

static inline int write_file(
	const int fd, const char * const file,
	const uint8_t * const data, const size_t sz)
{
	ssize_t len = sz;
	ssize_t ret = -1;
	const uint8_t *buf = data;
	while (len != 0 && ((ret = write(fd, buf, len)) != sz)) {
		printf("\tError: Not all data had been written (ret = %zd)\n", ret);
		if (ret == -1) {
			perror("\tGot error");
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		len -= ret;
		buf += ret;
		printf("\tError: Not full len wrote\n");
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////

static const char *input_container = "basic.wav";
static const char *input_data = "data.txt";
static const char *output_data_container = "updbasic.wav";
static const char *output_data = "upddata.txt";

static int hide_data()
{
	printf("hide_data() IN\n");

	printf("\t container open()\n");
	_cleanup_close_ int container_fd = -1;
	size_t container_sz = 0;
	int ret = open_file(
		input_container, &container_fd, &container_sz, false);
	if (ret != 0) {
		return -1;
	}

	printf("\t data open()\n");
	_cleanup_close_ int data_fd = -1;
	size_t data_sz = 0;
	ret = open_file(input_data, &data_fd, &data_sz, false);
	if (ret != 0) {
		perror("\t Got error");
		return -1;
	}

	size_t size_sz = sizeof(((StegoWave_t *)NULL)->hidden_data_size);
	double size_sz_max = (size_t)pow(2, size_sz * CHAR_BIT) - 1;
	printf("\t sizeof(hidden_data_size) bytes: %zu\n", size_sz);
	printf("\t hidden_data_size max value: %zu\n", (size_t)size_sz_max);
	printf("\t sizeof(uint16_t) bytes: %zu\n", sizeof(uint16_t));
	printf("\t UINT16_MAX: %u\n", UINT16_MAX);
	if (data_sz > (size_t)size_sz_max) {
		return -1;
	}
	if (data_sz > UINT16_MAX) {
		return -1;
	}

	size_t needed_sz = 0;
	ret = get_min_container_size(data_sz, &needed_sz);
	if (ret != 0) {
		return -1;
	}
	printf("\t needed sz: %ld\n", needed_sz);
	if (needed_sz > (container_sz - sizeof(StegoWave_t))) {
		return -1;
	}

	_cleanup_free_ uint8_t *data_buf = calloc(1, data_sz);
	if (data_buf == NULL) {
		return -1;
	}
	printf("\t data read()\n");
	ret = read_file(data_fd, data_buf, data_sz);
	if (ret != 0) {
		return -1;
	}

	_cleanup_free_ uint8_t *container_buf = calloc(1, container_sz);
	if (container_buf == NULL) {
		return -1;
	}
	printf("\t container read()\n");
	ret = read_file(container_fd, container_buf, container_sz);
	if (ret != 0) {
		return -1;
	}

	StegoWave_t *s = (StegoWave_t *)container_buf;
	s->hidden_data_size = data_sz;

	uint8_t *pc = container_buf + sizeof(StegoWave_t);
	size_t container_data_sz = container_sz - sizeof(StegoWave_t);
	ssize_t data_idx = 0;
	ssize_t container_idx = 0;
	printf("\t data_sz = %zu\n", data_sz);
	printf("\t container_sz = %zu\n", container_sz);
	printf("\t container_data_sz = %zu\n", container_data_sz);
	//printf("\n");
	for (
		data_idx = 0, container_idx = 0;
		data_idx < data_sz && container_idx < container_data_sz;
		++data_idx
	) {
		for (int i = 7; i >= 0; --i) {
/*
			printf("\t >>> container[%zu] = %u\n", container_idx, container_buf[container_idx]);
			printf("\t pc[%zu] = %u\n\t ", container_idx, pc[container_idx]);
			print_u8bits(pc[container_idx]);
			printf("\t data[%zu] = %u (%c)\n\t ", data_idx, data_buf[data_idx], data_buf[data_idx]);
			print_u8bits(data_buf[data_idx]);
			int16_t tmp0 = pc[container_idx];
*/
			uint8_t bit = get_bit(data_buf[data_idx], (unsigned char)i);
			bit == 0 ?
				clear_bit(&pc[container_idx], LSB_VAL)
				:
				set_bit(&pc[container_idx], LSB_VAL);
/*
			int16_t tmp1 = pc[container_idx];
			int16_t tmp = tmp0 - tmp1;
			printf("\t bit[%d] = %u\n", i, bit);
			printf("\t\t diff (%d - %d) = %d\n", tmp0, tmp1, tmp);
			if (tmp != 0 && tmp != 1 && tmp != -1) {
				printf("\t\t ERROR!\n");
				exit(-1);
			}
			printf("\t pc[%zu] = %u\n\t ", container_idx, pc[container_idx]);
			print_u8bits(pc[container_idx]);
			printf("\n");
*/
			container_idx += CONTAINER_BYTE_INC;
		}
	}
	if (data_idx < data_sz) {
		return -1;
	}

	_cleanup_close_ int data_container_fd = -1;
	size_t data_container_sz = 0;
	ret = open_file(
		output_data_container, &data_container_fd,
		&data_container_sz, true);
	if (ret != 0) {
		perror("\t Got error");
		return -1;
	}
	printf("\t data container write()\n");
	ret = write_file(
		data_container_fd, output_data_container,
		container_buf, container_sz);
	if (ret != 0) {
		return -1;
	}

	printf("hide_data() OUT\n");
	return 0;
}

static int unhide_data()
{
	printf("unhide_data() IN\n");

	_cleanup_close_ int data_container_fd = -1;
	size_t data_container_sz = 0;
	int ret = open_file(
		output_data_container, &data_container_fd,
		&data_container_sz, false);
	if (ret != 0) {
		perror("\t Got error");
		return -1;
	}

	_cleanup_free_ uint8_t *data_container_buf =
		calloc(1, data_container_sz);
	if (data_container_buf == NULL) {
		return -1;
	}
	printf("\t data container read()\n");
	ret = read_file(
		data_container_fd, data_container_buf, data_container_sz);
	if (ret != 0) {
		return -1;
	}

	StegoWave_t *s = (StegoWave_t *)data_container_buf;
	size_t data_sz = s->hidden_data_size;
	printf("\t data sz = %zu\n", data_sz);

	size_t needed_sz = 0;
	ret = get_min_container_size(data_sz, &needed_sz);
	if (ret != 0) {
		return -1;
	}
	printf("\t needed sz: %ld\n", needed_sz);
	if (data_container_sz <= sizeof(StegoWave_t)) {
		return -1;
	}
	if (needed_sz > (data_container_sz - sizeof(StegoWave_t))) {
		return -1;
	}

	_cleanup_free_ uint8_t *data_buf = calloc(1, data_sz);
	if (data_buf == NULL) {
		return -1;
	}

	uint8_t *pc = data_container_buf + sizeof(StegoWave_t);
	size_t pc_sz = data_container_sz - sizeof(StegoWave_t);
	ssize_t data_idx = 0;
	ssize_t container_idx = 0;
	for (
		data_idx = 0, container_idx = 0;
		data_idx < data_sz && container_idx < pc_sz;
		++data_idx
	) {
		for (int i = 7; i >= 0; --i) {
			uint8_t bit = get_bit(pc[container_idx], LSB_VAL);
			bit == 0 ?
				clear_bit(&data_buf[data_idx], (unsigned char)i)
				:
				set_bit(&data_buf[data_idx], (unsigned char)i);
			container_idx += CONTAINER_BYTE_INC;
		}
	}
	if (data_idx < data_sz) {
		return -1;
	}

	_cleanup_close_ int data_fd = -1;
	size_t data_sz_tmp = 0;
	ret = open_file(output_data, &data_fd, &data_sz_tmp, true);
	if (ret != 0) {
		perror("\t Got error");
		return -1;
	}
	printf("\t data container write()\n");
	ret = write_file(data_fd, output_data, data_buf, data_sz);
	if (ret != 0) {
		return -1;
	}

	printf("unhide_data() OUT\n");

	return 0;
}

///////////////////////////////////////////////////////////////////////////////

int main()
{
	hide_data();
	unhide_data();

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
