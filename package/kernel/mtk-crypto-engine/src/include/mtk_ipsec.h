#ifndef MTK_EIP93_IPSEC_H
#define MTK_EIP93_IPSEC_H


// for hashing only source (hash is saved in SAState)
// for encryption source & dest
// for encryption/hash SAState and SAData are needed (SAArc is equal to SAState)

typedef union
{
	struct
	{
		unsigned int opCode			: 3;	// 3 for hash, 0 encryption/esp (?!?)
		unsigned int direction		: 1;		// 1 decryption, 0 encryption
		unsigned int opGroup		: 2;		// 1 for encryption
		unsigned int padType		: 2;
		unsigned int cipher			: 4;	// 0 des, 1 3DES, 3 AES
		unsigned int hash			: 4;	// 0 MD5, 1 SHA1, 3 SHA256, F NULL (?!?)
		unsigned int reserved2		: 1;			
		unsigned int scPad			: 1;			
		unsigned int extPad			: 1;
		unsigned int hdrProc		: 1;	// 1 if we want to process also esp header
		unsigned int digestLength	: 4;	// lunghezza codifica digest in 32bit word (e.g. 256bit -> 8)
		unsigned int ivSource		: 2;	// 3 load IV from PRNG, 0 (load from state ?!?)
		unsigned int hashSource		: 2; 	// 3 no load hash source
		unsigned int saveIv			: 1;					
		unsigned int saveHash		: 1;					
		unsigned int reserved1		: 2;	
	} bits;
	unsigned int word;
		
} saCmd0_t;

typedef union
{
	struct
	{
		unsigned int copyDigest		: 1;
		unsigned int copyHeader		: 1;
		unsigned int copyPayload	: 1;
		unsigned int copyPad		: 1;
		unsigned int reserved4		: 4;
		unsigned int cipherMode		: 2;	// 1 cbc, 0 ecb
		unsigned int reserved3		: 1;
		unsigned int sslMac			: 1;
		unsigned int hmac			: 1;   // 1 enable hmac (hash with key)
		unsigned int byteOffset		: 1;
		unsigned int reserved2		: 2;
		unsigned int hashCryptOffset: 8;
#if 1			
		unsigned int arc4KeyLen		: 5;
		unsigned int seqNumCheck	: 1;
		unsigned int reserved1		: 2;
#else		
		unsigned int aesKeyLen		: 3;   // 2 AES128, 3 AES192, 4 AES256
		unsigned int reserved1		: 1;
		unsigned int aesDecKey		: 1;
		unsigned int seqNumCheck	: 1;
		unsigned int reserved0		: 2;
#endif
		
	} bits;
	unsigned int word;
		
} saCmd1_t;

typedef struct saRecord_s
{
	saCmd0_t	 saCmd0;
	saCmd1_t	 saCmd1;
	unsigned int saKey[8];
	unsigned int saIDigest[8];  // sono l'inner hash da passare ad ipsec
	unsigned int saODigest[8];  // sono l'outer hash da passare ad ipsec
	unsigned int saSpi;
	unsigned int saSeqNum[2];
	unsigned int saSeqNumMask[2];
	unsigned int saNonce;

} saRecord_t;

typedef struct saState_s
{
	unsigned int stateIv[4];
	unsigned int stateByteCnt[2];
	unsigned int stateIDigest[8];   // contiene il risultato della funzione di hash

} saState_t;






#endif

