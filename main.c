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
#include <string.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <openssl/evp.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

///////////////////////////////////////////////////////////////////////////////

/*
https://github.com/emirat8/LSB-Video-Steganography
https://medium.com/better-programming/a-guide-to-video-steganography-using-python-4f010b32a5b7
https://link.springer.com/article/10.1007/s11042-023-14844-w
https://medium.com/@vedanshvijay/steganography-5d9d8a557587
https://github.com/JavDomGom/videostego

https://www.mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/WAVE.html
https://docs.fileformat.com/audio/wav/
https://isip.piconepress.com/projects/speech/software/tutorials/production/fundamentals/v1.0/section_02/s02_01_p05.html
http://soundfile.sapp.org/doc/WaveFormat/
https://www.loc.gov/preservation/digital/formats/fdd/fdd000001.shtml
https://www.tpx.com/support/wav-file-specifications/
https://www.tpx.com/support/wav-file-specifications/


https://medium.com/@amit.kulkarni/encrypting-decrypting-a-file-using-openssl-evp-b26e0e4d28d4
https://stackoverflow.com/questions/44246967/how-to-convert-aes-encrypt-in-counter-mode-to-evp-interfaces
https://forums.developer.nvidia.com/t/problem-with-openssl-undefined-reference-to-crypto-gcm128-init/171249/2
https://stackoverflow.com/questions/52369124/what-is-exact-alternate-api-instead-of-aes-ctr128-encrypt-from-openssl-1-1-0
https://stackoverflow.com/questions/29441005/aes-ctr-encryption-and-decryption
https://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/
https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
*/

/* LSB - least significant bit */

// sudo apt install wavbreaker
// wavinfo basic.wav

/* Naive Example */

// gcc main.c
// gcc main.c -lm
// -std=c2x
// -std=gnu11
// ./a.out


// sudo apt-get install libssl-dev
// gcc -Wall -Wextra -Werror -static -o myApp \
// 	source1.o source2.o common.o \
// 	-Lopenssl/openssl-X/ -lssl -lcrypto -Iopenssl/openssl-X/include

// reset; gcc -DDEBUG_MSG main.c -lm -lssl -lcrypto
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

//#define DEBUG_MSG

///////////////////////////////////////////////////////////////////////////////

#ifdef DEBUG_MSG
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

	for (int i = (CHAR_BIT - 1); i >= 0; --i) {
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
#endif

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

static inline void insert_bit(
	unsigned char *val, unsigned char id, unsigned char bit)
{
	if (bit != 0 && bit != 1) {
		abort();
	}

	if (bit == 0) {
		clear_bit(val, id);
	} else {
		set_bit(val, id);
	}

	return;
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

//#define CONTAINER_BYTE_INC (4)
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
/*
    	// each 4th byte used
	if (__builtin_mul_overflow(tmp, CONTAINER_BYTE_INC, &tmp)) {
        	return -1;
    	}
*/
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
		printf("\tError: Not all data had been written (ret = %zd)\n",
			ret);
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

static const unsigned char const key_arr[AES_BLOCK_SIZE] = {};
static const unsigned char const iv_arr[AES_BLOCK_SIZE] = {};

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

// ctr, cfb, ofb
static int encrypt_data_aes_ctr(
	const uint8_t * const raw_data, uint8_t *enc_data, size_t data_sz)
{
	size_t enc_data_sz = 0;
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		handleErrors();
	}
	if (1 != EVP_EncryptInit_ex(
		ctx, EVP_aes_128_ctr(), NULL, key_arr, iv_arr)) {
		handleErrors();
	}
	if (1 != EVP_EncryptUpdate(
		ctx, enc_data, &len, raw_data, data_sz)) {
		handleErrors();
	}
	enc_data_sz = (size_t)len;
	if (1 != EVP_EncryptFinal_ex(ctx, enc_data + len, &len)) {
		handleErrors();
	}
	enc_data_sz += (size_t)len;
	EVP_CIPHER_CTX_free(ctx);

	if (enc_data_sz != data_sz) {
		exit(-1);
	}

	return 0;
}

static int decrypt_data_aes_ctr(
	const uint8_t * const enc_data, uint8_t *raw_data, size_t enc_data_sz)
{
	size_t raw_data_sz = 0;
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		handleErrors();
	}
	if (1 != EVP_DecryptInit_ex(
		ctx, EVP_aes_128_ctr(), NULL, key_arr, iv_arr)) {
		handleErrors();
	}
	if (1 != EVP_DecryptUpdate(
		ctx, raw_data, &len, enc_data, enc_data_sz)) {
		handleErrors();
	}
	raw_data_sz = (size_t)len;
	if (1 != EVP_DecryptFinal_ex(ctx, raw_data + len, &len)) {
		handleErrors();
	}
	raw_data_sz += len;
	EVP_CIPHER_CTX_free(ctx);

	if (raw_data_sz != enc_data_sz) {
		exit(-1);
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////

static inline bool is_wav_file(
	const char * const file_name,
	const uint8_t * const file, const size_t sz)
{
	if (file_name == NULL || file == NULL) {
		return false;
	}
	if (sz == 0 || sz <= sizeof(StegoWave_t)) {
		return false;
	}

	size_t str_len = strlen(file_name);
	if (str_len < strlen("x.wav")) {
		return false;
	}
	const char *ps = file_name + (str_len - strlen(".wav"));
	int str_cmp = strcmp(ps, ".wav");
	if (str_cmp != 0) {
		return false;
	}

	StegoWave_t *s = (StegoWave_t *)file;
	int res = memcmp(s->header.FileTypeBlocID, "RIFF", 4);
	if (res != 0) {
		return false;
	}
	res = memcmp(s->header.FileFormatID, "WAVE", 4);
	if (res != 0) {
		return false;
	}
	res = memcmp(s->header.FormatBlocID, "fmt ", 4);
	if (res != 0) {
		return false;
	}

	printf("\t\t\t Is .wav file\n");
	return true;	
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
	if (container_sz <= sizeof(StegoWave_t)) {
		return -1;
	}
	size_t container_data_sz = container_sz - sizeof(StegoWave_t);
	if (needed_sz > container_data_sz) {
		return -1;
	}
	// CONTAINER_BYTE_INC
	const ssize_t container_byte_inc_real =
		(container_data_sz / data_sz) / CHAR_BIT;
	if (container_byte_inc_real <= 0) {
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

	(void)is_wav_file(input_container, container_buf, container_sz);

	StegoWave_t *s = (StegoWave_t *)container_buf;
	s->hidden_data_size = data_sz;

	_cleanup_free_ uint8_t *enc_data_buf = calloc(1, data_sz);
	if (enc_data_buf == NULL) {
		return -1;
	}
	ret = encrypt_data_aes_ctr(data_buf, enc_data_buf, data_sz);
	if (ret != 0) {
		return -1;
	}

	uint8_t *pc = container_buf + sizeof(StegoWave_t);
	size_t pc_sz = container_sz - sizeof(StegoWave_t);
	ssize_t data_idx = 0;
	ssize_t container_idx = 0;
	printf("\t data_sz = %zu\n", data_sz);
	printf("\t container_sz = %zu\n", container_sz);
	printf("\t pc_sz = %zu\n", pc_sz);
	for (
		data_idx = 0, container_idx = 0;
		data_idx < data_sz && container_idx < pc_sz;
		++data_idx
	) {
		for (int i = (CHAR_BIT - 1); i >= 0; --i) {
#ifdef DEBUG_MSG
			int old_val = pc[container_idx];
#endif
			uint8_t bit = get_bit(enc_data_buf[data_idx], (unsigned char)i);
			insert_bit(&pc[container_idx], LSB_VAL, bit);
#ifdef DEBUG_MSG
			int new_val = pc[container_idx];
			int res_val = new_val - old_val;
			if (res_val != 0 && res_val != 1 && res_val != -1) {
				exit(-2);
			}
			assert(res_val == 0 || res_val == 1 || res_val == -1);
#endif
			//container_idx += CONTAINER_BYTE_INC;
			container_idx += container_byte_inc_real;
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

	(void)is_wav_file(
		output_data_container, data_container_buf, data_container_sz);

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
	size_t container_data_sz = data_container_sz - sizeof(StegoWave_t);
	if (needed_sz > container_data_sz) {
		return -1;
	}
	// CONTAINER_BYTE_INC
	const ssize_t container_byte_inc_real =
		(container_data_sz / data_sz) / CHAR_BIT;
	if (container_byte_inc_real <= 0) {
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
		for (int i = (CHAR_BIT - 1); i >= 0; --i) {
			uint8_t bit = get_bit(pc[container_idx], LSB_VAL);
			insert_bit(&data_buf[data_idx], (unsigned char)i, bit);
			//container_idx += CONTAINER_BYTE_INC;
			container_idx += container_byte_inc_real;
		}
	}
	if (data_idx < data_sz) {
		return -1;
	}

	_cleanup_free_ uint8_t *dec_data_buf = calloc(1, data_sz);
	if (dec_data_buf == NULL) {
		return -1;
	}
	ret = decrypt_data_aes_ctr(data_buf, dec_data_buf, data_sz);
	if (ret != 0) {
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
	ret = write_file(data_fd, output_data, dec_data_buf, data_sz);
	if (ret != 0) {
		return -1;
	}

	printf("unhide_data() OUT\n");

	return 0;
}

///////////////////////////////////////////////////////////////////////////////

int main()
{
	(void)hide_data();
	(void)unhide_data();

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
