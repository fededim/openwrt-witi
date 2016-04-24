
#include "mtk_baseDefs.h"
#include "mtk_hwAccess.h"
#include "mtk_AdapterInternal.h"
#include "mtk_hwDmaAccess.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <asm/mach-ralink/rt_mmap.h>
#include <asm/mach-ralink/surfboardint.h>
#include "mtk_pecApi.h"
#include "mtk_interrupts.h"
#include "mtk_arm.h"

#include "mtk_smartApi.h"

//#include <net/mtk_esp.h>

static struct proc_dir_entry *entry;

static bool Adapter_IsInitialized = false;


static bool Adapter_Init(void)
{
    if (Adapter_IsInitialized != false)
    {
        printk("Adapter_Init: Already initialized\n");
        return true;
    }


    if (!HWPAL_DMAResource_Init(1024))
    {
       printk("HWPAL_DMAResource_Init failed\n");
       return false;
    }

    if (!Adapter_EIP93_Init())  // configures also interrupts in the chip
    {
        printk("Adapter_EIP93_Init failed\n");
	return false;
    }

#ifdef ADAPTER_EIP93PE_INTERRUPTS_ENABLE
    Adapter_Interrupts_Init(SURFBOARDINT_CRYPTO);
#endif

    Adapter_IsInitialized = true;

    return true;
}


static void Adapter_UnInit(void)
{
    if (!Adapter_IsInitialized)
    {
        printk("Adapter_UnInit: Adapter is not initialized\n");
        return;
    }

    Adapter_IsInitialized = false;



    Adapter_EIP93_UnInit();

#ifdef ADAPTER_EIP93PE_INTERRUPTS_ENABLE
    Adapter_Interrupts_UnInit();
#endif

    HWPAL_DMAResource_UnInit();
}




// packet result functions

extern unsigned int *pCmdRingBase, *pResRingBase; //uncached memory address
extern void mtk_interruptHandler_descriptorDone(void);

#define EIP93_RING_SIZE		((ADAPTER_EIP93_RINGSIZE_BYTES)>>5)
#define EIP93_REG_BASE		(RALINK_CRYPTO_ENGINE_BASE)
#define PE_CTRL_STAT		0x00000000
#define PE_CD_COUNT		0x00000090
#define	PE_RD_COUNT		0x00000094
#define PE_RING_PNTR		0x00000098
#define PE_CONFIG		0x00000100
#define PE_DMA_CONFIG		0x00000120
#define PE_ENDIAN_CONFIG	0x000001d0
//#define dma_cache_wback_inv(start, size) _dma_cache_wback_inv(start,size)
#define K1_TO_PHY(x)		(((unsigned int)x) & 0x1fffffff)
#define WORDSWAP(a)     	((((a)>>24)&0xff) | (((a)>>8)&0xff00) | (((a)<<8)&0xff0000) | (((a)<<24)&0xff000000))
#define DESCP_SIZE		32
#define EIP93_RING_BUFFER	24

static unsigned int cmdRingIdx, resRingIdx;
static uint32_t *pEip93RegBase = (uint32_t *)EIP93_REG_BASE;

unsigned int eip93_descr_size;
spinlock_t putlock, getlock;
int mtkDMAAlign = 0;

// data is always the 0 value passed in the declaration

void eip93_handler_resultGet(unsigned long data)
{
	EIP93ResultPacket *packet;
	bool first=true;

	printk("Mtk-Crypto-Engine: result tasklet starts...");

	// probably we need take getlock, otherwise the packet result order could be
	while ((packet=EIP93_ARM_Packet_Get())!=NULL) {
		// we perform callback to the user
		packet->InputPacket->Callback(packet);

		// Deallocate everything
		EIP93_FreePacket(packet->InputPacket);  // deallocates packet
		kfree(packet);				// deallocates resultpacket

		first=false;
	}

	if (first)
		printk("Mtk-Crypto-Engine: WARNING...interrupt received and no result found (is it drunk ?)");

	// clear interrupt bit
	Adapter_Interrupt_ClearAndEnable(IRQ_RDR_THRESH_IRQ);   // check if it is the correct interrupt...
}


#ifdef WORKQUEUE_BH
static DECLARE_WORK(mtk_interrupt_BH_result_wq, eip93_handler_resultGet);
#else
static DECLARE_TASKLET( eip93_result_tasklet, eip93_handler_resultGet, 0);
#endif

// we schedule the handler in another task
static void mtk_interruptHandler_done(void)
{
	printk("Mtk-Crypto-Engine: interrupt received, scheduling tasklet");
#ifdef WORKQUEUE_BH
	schedule_work(&mtk_interrupt_BH_result_wq);
#else	
	tasklet_hi_schedule(&eip93_result_tasklet);
#endif
}


void  mtk_cryptoengine_init(void)
{
	mtkDMAAlign = 4;//dma_get_cache_alignment();
	printk("Mtk-Crypto-Engine: %s %s initializing mtkDMAAlign %d...\n",__DATE__,__TIME__,mtkDMAAlign);
	spin_lock_init(&putlock);
	spin_lock_init(&getlock);
	write_c0_config7((read_c0_config7()|(1<<8)));   // write into MIPS register
		
	//eip93 info init
	cmdRingIdx = ioread32(pEip93RegBase + (PE_RING_PNTR >> 2)) & (BIT_10-1); 
	resRingIdx = (ioread32(pEip93RegBase + (PE_RING_PNTR >> 2)) >>16) & (BIT_10-1);
#ifdef WORKQUEUE_BH
	INIT_WORK(&mtk_interrupt_BH_result_wq, eip93_handler_resultGet);
#else
	tasklet_init(&eip93_result_tasklet, eip93_handler_resultGet , 0);
#endif
	//eip93 interrupt mode init
	Adapter_Interrupt_ClearAndEnable(IRQ_RDR_THRESH_IRQ);
	Adapter_Interrupt_SetHandler(IRQ_RDR_THRESH_IRQ, mtk_interruptHandler_done);
	
	//EndianSwap Setting for C.L.'s new POF for fix no_word_alignment  (put right b4 kick CryptoEngine)
	iowrite32(0x00000700, pEip93RegBase + (PE_CONFIG >> 2));
	iowrite32(0x00e400e4, pEip93RegBase + (PE_ENDIAN_CONFIG >> 2));
}


void TestHash_Cbk(struct EIP93ResultPacket *p) {
	printk("TestHash_Cbk received Length %d\n",p->Length.bits.length);

	IPSEC_SAData *sadata=(IPSEC_SAData *) p->InputPacket->SAData->kernelAddr;
	IPSEC_SAState *sastate=(IPSEC_SAState *) p->InputPacket->SAState->kernelAddr;
	
	IPSEC_DumpState(sastate);
}


void *TestHash(char *input, int *len) {
	EIP93Packet *p;
	IPSEC_SAData *sadata;
	IPSEC_SAState *sastate;

	p=EIP93_AllocPacket(&TestHash_Cbk);

	sadata=(IPSEC_SAData *) p->SAData->kernelAddr;
	sastate=(IPSEC_SAState *) p->SAState->kernelAddr;

	// Set hash operation
	sadata->cmd0.bits.opCode=OPCODE_HASH;
	sadata->cmd0.bits.hash=HASH_MD5;
	sadata->cmd0.bits.digestLength=DIGESTLENGTH_128b;
	sadata->cmd0.bits.hashSource=HASHSOURCE_NOLOAD;
	sadata->cmd0.bits.saveHash = 0x1;  // don't know for what is needed, for now we leave it

	p->SrcData=DmaBuffer_Map(input,len,DMA_TO_DEVICE);

	if (EIP93_ARM_Packet_Put(p)!=1) {
		printk("Error while sending packet to crypto engine!\n");
	}
	else 
		printk("Hash packet request queued waiting for callback\n");
}




int __init VDriver_Init(void)
{    
	char * input="Prova hash";

	if (!Adapter_Init()) {
		printk("Mtk-Crypto-Engine: Adapter_Init failed!\n");
		return -1;
	}

	if (PEC_Init(NULL) == PEC_ERROR_BAD_USE_ORDER) {
		printk("Mtk-Crypto-Engine: PEC is already initialized!\n");
		return -1;
	}
    
	mtk_cryptoengine_init();
    
	eip93_descr_size=EIP93_ARM_DESCRIPTOR_SIZE();

	// Init DMA memory pools
	InitDMAPoolsForSADataStateArc4(128,56,0);

	printk("Mtk-Crypto-Engine: successfully initialized\n");

	TestHash(input,strlen(input));

	return 0;   // success
}



void __exit VDriver_Exit(void)
{
    Adapter_UnInit();
	
    PEC_UnInit();
}

MODULE_LICENSE("Proprietary");

module_init(VDriver_Init);
module_exit(VDriver_Exit);
