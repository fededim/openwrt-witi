#ifndef EIP93_SMARTAPI_H
#define EIP93_SMARTAPI_H

#include <linux/slab.h>
#include <linux/dmapool.h>
#include <linux/dma-mapping.h>


typedef struct DmaBuffer {
	void *kernelAddr;
	dma_addr_t dmaAddr;
	size_t size;
	enum { POOLED, COHERENT, MAPPED } allocType;
	struct dma_pool *allocPool;  // pointer to the alloc pool, if has been allocated through a pool
	enum dma_data_direction mapDirection; // for incoherent allocations (needed by unmap function)
} DmaBuffer;

// Dma SmartApi

bool InitDMAPoolsForSADataStateArc4(int sadatasize, int sastatesize, int saarc4size);
void UnInitDMAPoolsForSADataStateArc4(void);
// This buffer is consistent, i.e. all writes from cpu are written back to memory and all write from a device invalidate cpu cache on the
// address automatically. It has the implicit direction DMA_BIDIRECTIONAL. They do not need any sync operation.
DmaBuffer *DmaBuffer_Alloc(size_t size);
DmaBuffer *DmaBuffer_AllocPool(struct dma_pool *pool, int size); // we need to pass again size because we can't get it from pool structure
// This buffer is inconsistent, i.e. all writes from cpu are not written back to memory and all writes from a device do not invalidate cpu 
// cache on the address automatically. You must specify a map direction . They need a sync operation.
DmaBuffer *DmaBuffer_Map(void *kaddr,int size,enum dma_data_direction direction);
void DmaBuffer_Free (DmaBuffer * buf);


// CryptoEngine packet structure

typedef union
{
	struct
	{
		unsigned int hostReady	: 1;
		unsigned int peReady	: 1;
		unsigned int reserved	: 1;
		unsigned int initArc4	: 1;
		unsigned int hashFinal	: 1;
		unsigned int haltMode	: 1;
		unsigned int prngMode	: 2;
		unsigned int padValue	: 8;
		unsigned int errStatus	: 8;
		unsigned int padCrtlStat: 8;
	} bits;
	unsigned int word;
		
} EIP93Packet_ControlStat;

typedef union
{
	struct
	{
		unsigned int length	: 20;
		unsigned int reserved	: 2;
		unsigned int hostReady	: 1;
		unsigned int peReady	: 1;
		unsigned int byPass	: 8;	
	} bits;	
	unsigned int word;
		
} EIP93Packet_Length;


struct EIP93ResultPacket;

typedef void (*EIP93_ResultCallback)(struct EIP93ResultPacket *packet);


typedef struct EIP93Packet
{
    // control fields for the command descriptor
    // EIP93_CommandDescriptor_Control_MakeWord helper function
    // can be used for obtaining this word
    EIP93Packet_ControlStat ControlStat;

    // source packet data, has to be provided by the caller:
    // physical address, understandable by Device
    DmaBuffer *SrcData;

    // length of source packet data in words that must bypass
    // the Packet Engine and are directly copied from
    // the source packet buffer to the destination packet buffer
    uint32_t BypassWords;

    // where to place the result data, has to be allocated by the caller:
    // physical address, understandable by Device
    DmaBuffer *DstData;

    // SA data, has to be allocated and filled in by the caller:
    // physical address, understandable by Device
    DmaBuffer *SAData;

    //SA State,has to be allocated and filled in by the caller:
    // physical address, understandable by Device
    DmaBuffer *SAState;

    DmaBuffer *SAArc4;  // if NULL it will set equal to SAState

    // copy through content from command to result descriptor
    void *Userdata;

    EIP93Packet_Length Length;

    EIP93_ResultCallback Callback;

#ifdef EIP93_ARM_NUM_OF_DESC_PADDING_WORDS
    // 0 or more padding word values
    // these values will be placed by _PacketPut
    // to additional padding words in a command descriptor passed
    // to the device.
    uint32_t PaddingWords[EIP93_ARM_NUM_OF_DESC_PADDING_WORDS];
#endif

} EIP93Packet;


typedef struct EIP93ResultPacket
{
    EIP93Packet_ControlStat ControlStat;
    EIP93Packet_Length Length;

    EIP93Packet *InputPacket;
} EIP93ResultPacket;


EIP93Packet *EIP93_AllocPacket(EIP93_ResultCallback cbk);
EIP93Packet **EIP93_AllocPackets(int numPackets,EIP93_ResultCallback cbk);
void EIP93_FreePacket(EIP93Packet *packet);
void DumpBinary(void *addr, int len, int longperrow);
void DumpDMA(DmaBuffer *buf, int maxlen,int longperrow, char *bufname);
void EIP93_DumpPacket(EIP93Packet *packet, char *methodname);
void EIP93_DumpRing (unsigned int *pCrd,int index,char *methodname);
void EIP93_FreePackets(EIP93Packet **packets, int num);
int EIP93_ARM_Packet_Put(EIP93Packet *packet);
EIP93ResultPacket *EIP93_ARM_Packet_Get(void);


// Ipsec custom SAData and SAState structures

// for hashing only source (hash is saved in SAState)
// for encryption source & dest
// for encryption/hash SAState and SAData are needed (SAArc is equal to SAState)


#define	OPCODE_HASH	3

#define HASH_MD5	0

#define DIGESTLENGTH_128b	4


#define HASHSOURCE_NOLOAD	3

typedef union
{
	struct
	{
		unsigned int opCode		: 3;	// 3 for hash, 0 encryption/esp (?!?)
		unsigned int direction		: 1;	// 1 decryption, 0 encryption
		unsigned int opGroup		: 2;	// 1 for encryption
		unsigned int padType		: 2;
		unsigned int cipher		: 4;	// 0 des, 1 3DES, 3 AES
		unsigned int hash		: 4;	// 0 MD5, 1 SHA1, 3 SHA256, F NULL (?!?)
		unsigned int reserved2		: 1;			
		unsigned int scPad		: 1;			
		unsigned int extPad		: 1;
		unsigned int hdrProc		: 1;	// 1 if we want to process also esp header
		unsigned int digestLength	: 4;	// lunghezza codifica digest in 32bit word (e.g. 256bit -> 8)
		unsigned int ivSource		: 2;	// 3 load IV from PRNG, 0 (load from state ?!?)
		unsigned int hashSource		: 2; 	// 3 no load hash source
		unsigned int saveIv		: 1;					
		unsigned int saveHash		: 1;					
		unsigned int reserved1		: 2;	
	} bits;
	unsigned int word;
		
} IPSEC_SAData_Cmd0;

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
		
} IPSEC_SAData_Cmd1;

typedef struct IPSEC_SAData
{
	IPSEC_SAData_Cmd0	 cmd0;
	IPSEC_SAData_Cmd1	 cmd1;
	unsigned int saKey[8];
	unsigned int saIDigest[8];  // sono l'inner hash da passare ad ipsec
	unsigned int saODigest[8];  // sono l'outer hash da passare ad ipsec
	unsigned int saSpi;
	unsigned int saSeqNum[2];
	unsigned int saSeqNumMask[2];
	unsigned int saNonce;

} IPSEC_SAData;

typedef struct IPSEC_SAState
{
	unsigned int stateIv[4];
	unsigned int stateByteCnt[2];
	unsigned int stateIDigest[8];   // contiene il risultato della funzione di hash

} IPSEC_SAState;


// Functions
void IPSEC_DumpState (IPSEC_SAState *s);

#endif

