#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/sched.h>

#include <linux/delay.h>
#include <linux/string.h>

#include <net/ip.h>
#include <asm/io.h>
#include <asm/mach-ralink/rt_mmap.h>
#include "mtk_cAdapter.h"
#include "mtk_baseDefs.h"         // uint32_t
#include "mtk_pecApi.h"            // PEC_* (the API we implement here)
#include "mtk_dmaBuf.h"         // DMABuf_*
#include "mtk_hwDmaAccess.h"      // HWPAL_Resource_*
#include "mtk_cLib.h"               // memcpy
#include "mtk_AdapterInternal.h"
#include "mtk_interrupts.h"
#include "mtk_arm.h"        // driver library API we will use
#include "mtk_descp.h" // for parsing result descriptor

#include <net/mtk_esp.h>
#include "mtk_ipsec.h"
#include <linux/skbuff.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>


extern spinlock_t putlock, getlock;

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


#ifdef CONFIG_L2TP
#define BUFFER_MEMCPY	1
#define SKB_HEAD_SHIFT	1
#endif

#ifdef MCRYPTO_DBG
#define ra_dbg 	printk
#else
#define ra_dbg(fmt, arg...) do {}while(0)
#endif

static int pskb_alloc_head(struct sk_buff *skb, u8* data, u32 size, int offset);
int copy_data_head(struct sk_buff *skb, int offset);
int copy_data_bottom(struct sk_buff *skb, int offset);

#ifdef MCRYPTO_DBG
static void skb_dump(struct sk_buff* sk, const char* func,int line) {
        unsigned int i;

        ra_dbg("(%d)skb_dump: [%s] with len %d (%08X) headroom=%d tailroom=%d\n",
                line,func,sk->len,sk,
                skb_headroom(sk),skb_tailroom(sk));

        for(i=(unsigned int)sk->head;i<=(unsigned int)sk->data + sk->len;i++) {
                if((i % 16) == 0)
                        ra_dbg("\n");
                if(i==(unsigned int)sk->data) printk("{");
                //if(i==(unsigned int)sk->h.raw) printk("#");
                //if(i==(unsigned int)sk->nh.raw) printk("|");
                //if(i==(unsigned int)sk->mac.raw) printk("*");
                ra_dbg("%02x ",*((unsigned char*)i));
                if(i==(unsigned int)(sk->tail)-1) printk("}");
        }
        ra_dbg("\n");
}
#else
#define skb_dump(x,y,z) do {}while(0)
#endif

/************************************************************************
*              P R I V A T E     F U N C T I O N S
*************************************************************************
*/



/*_______________________________________________________________________
**function name: mtk_packet_put
**
**description:
*   put command descriptor into EIP93's Command Descriptor Ring and
*	then kick off EIP93.
**parameters:
*   cmdDescp -- point to the command handler that stores the needed
*		info for the command descriptor.
*	skb -- the packet for encryption/decryption
**global:
*   none
**return:
*   0 -- success.
**call:
*   none
**revision:
*   1.Trey 20120209
**_______________________________________________________________________*/

// MAIN FUNCTION WHICK TALKS WITH THE PACKET ENGINE
// sk_buff is a standard linux structure containing network packets. it is structured as a double linked list

// in pratica aumenta il buffer circolare condiviso, lo riempe e scrive il valore 1 in un registro del packet engine
// i buffer di IO sono precedentemente allocati dal driver e sono passati all'interno di un pacchetto di 8 long (elemento del ring buffer)
// insieme all'operazione da fare al packet engine
static int mtk_packet_put(eip93DescpHandler_t *cmdDescp, struct sk_buff *skb)  //skb == NULL when in digestPreCompute
{
	unsigned int *pCrd = pCmdRingBase;
	ipsecEip93Adapter_t *currAdapterPtr;
	unsigned int addedLen;
	unsigned int *addrCurrAdapter;
	unsigned long flags;
	u32* pData = NULL;
	dma_addr_t pDataPhy;
	
	//spin_lock_irqsave(&putlock, flags);

	if(cmdRingIdx == EIP93_RING_SIZE)
	{
		cmdRingIdx = 0;
	}
	pCrd += (cmdRingIdx << 3); //cmdRingIdx*8 (a cmdDescp has 8 words!)  // it doesn't take into account added padding words no problem!
	cmdRingIdx++;

	// TOZZO
	pCrd[3] = cmdDescp->saAddr.phyAddr;
	pCrd[4] = cmdDescp->stateAddr.phyAddr;
	pCrd[5] = cmdDescp->arc4Addr.phyAddr;  // it's the same as stateAddr ?!?

	// skb è una struttura che passa i pacchetti di rete, pertanto se dobbiamo cifrare/decifrare dei dati
	if(likely(skb != NULL))
	{
		addrCurrAdapter = (unsigned int *) &(skb->cb[36]);   // extract a previous recorded reference inside a 40 bytes field (cb) of packet buffer structure
		currAdapterPtr = (ipsecEip93Adapter_t *)(*addrCurrAdapter);
		addedLen = currAdapterPtr->addedLen;  // è dell'eventuale padding aggiunto al pacchetto

		// performs cpu cache write back to memory and invalidate before starting engine
		dma_cache_wback_inv((unsigned long)(skb->data), (skb->len + addedLen) & (BIT_20 - 1));
		
#if defined (BUFFER_MEMCPY)	
		if ((u32)(skb->data)%mtkDMAAlign)   // se il pacchetto non è allocato su un indirizzo multiplo di 4 (mtkDMAAlign)
		{	
#if defined (SKB_HEAD_SHIFT)
			int offset, alloc_size;
			offset = mtkDMAAlign-(u32)(skb->data)%mtkDMAAlign;  // delta indirizzi per allinearsi a multipli di mtkDMAAlign
			pData = NULL;
#else				
			pData = kmalloc(skb->len + addedLen, GFP_KERNEL);  // alloco nuovo pacchetto
#endif
			*(unsigned int *) &(skb->cb[40]) = (u32)pData;  // cb field of skb of 40 chars the next field is packet length...I think that this method overwrite the len field but why on earth do that in this way. Understood: it saves the virtual address because the address returned by cryptoengine after having processed the packet are physical or dma so they are useless.
			if(pData==NULL)
			{	
				// TOZZO non sono riuscito ad allocare la memoria (faccio l'head shift o merda colossale)
#if defined (SKB_HEAD_SHIFT)
				pCrd[1] = K1_TO_PHY(skb->data);   // dati pacchetto
				pCrd[2] = K1_TO_PHY(skb->data+offset);  // dati pacchetto con inizio allineato al dma (avrei detto però -)
#else
				printk("mtk_packet_put allocate null\n");
				pCrd[1] = K1_TO_PHY(skb->data);   // dati pacchetto
				pCrd[2] = K1_TO_PHY(skb->data);   // dati pacchetto
#endif
			}
			else
			{					
				// Use mmu to retrieve the physical address of newly allocated pData and allocate it to crypto for transfer
				pDataPhy = dma_map_single(NULL, pData, skb->len + addedLen, PCI_DMA_FROMDEVICE);
				if (pDataPhy==NULL)
				{
					printk("dma_map_single pDataPhy NULL\n");
				}
				pCrd[1] = K1_TO_PHY(skb->data);   // dati pacchetto
				pCrd[2] = pDataPhy;	// boh è una struttura nuova allocata con dati random (neanche zero) uscita ? 		
			}
		}
		else
#endif
		{	
			pCrd[1] = K1_TO_PHY(skb->data);
			pCrd[2] = K1_TO_PHY(skb->data);
		}

		// TOZZO
		pCrd[6] = (unsigned int)skb;   // probabilmente è uno userdata che viene ripassato così com'è dal packet engine
#if 0
	    /*When encryption, it is necessary to consider when the packet size is greater than 200, and in tunnel mode (l2tpeth0), 
 			before the packet length longer (+4), otherwise there will be untied.   */
		if ((currAdapterPtr->isEncryptOrDecrypt==1) && (skb->len > 200) && !(skb->dev->name == NULL))
		{
			if(strcmp(skb->dev->name,"l2tpeth0") == 0)
			{		
				pCrd[7] = ((skb->len+4) & (BIT_20 - 1)) | (cmdDescp->peLength.word & (~(BIT_22 - 1)));
			}else{
				pCrd[7] = ((skb->len) & (BIT_20 - 1)) | (cmdDescp->peLength.word & (~(BIT_22 - 1)));
			}
		}
		else
#endif		
		{
			// TOZZO
			pCrd[7] = ((skb->len) & (BIT_20 - 1)) | (cmdDescp->peLength.word & (~(BIT_22 - 1)));  // lunghezza dati
		}

	}
	// se non abbiamo dati da cifrare/hashare
	else
	{
		pCrd[1] = cmdDescp->srcAddr.phyAddr;
		pCrd[2] = cmdDescp->srcAddr.phyAddr;
		pCrd[6] = cmdDescp->userId;
		pCrd[7] = cmdDescp->peLength.word;
	}
	pCrd[0] = cmdDescp->peCrtlStat.word;  // è il comando da impartire al ring buffer (ha anche dei bit di stato)

	// wmb invalidates all the memory which is written subsequently it's call ?!?
	//prevent from inconsistency of HW DMA and SW memory access
	wmb();
	iowrite32(1, pEip93RegBase + (PE_CD_COUNT >> 2)); //PE_CD_COUNT/4	// 1 è probabilmente il numero di pacchetto accodati
	
	//spin_unlock_irqrestore(&putlock, flags);

	return 0; //success
}



/*_______________________________________________________________________
**function name: mtk_packet_get
**
**description:
*   get result descriptor from EIP93's Result Descriptor Ring.
**parameters:
*   resDescp -- point to the result handler that stores the needed
*		info for the result descriptor.
**global:
*   none
**return:
*   0  -- EIP93 has no result yet.
*   1  -- EIP93 has results ready.
*   -1 -- the current result is wrong!
**call:
*   none
**revision:
*   1.Trey 20120209
**_______________________________________________________________________*/
static int mtk_packet_get(eip93DescpHandler_t *resDescp)
{
	unsigned int *pRrd = pResRingBase;
	unsigned int done1, done2, err_sts, PktCnt, timeCnt = 0;
	unsigned long flags;
	struct sk_buff *skb = NULL;
	int retVal;

	ipsecEip93Adapter_t *currAdapterPtr;
	unsigned int *addrCurrAdapter;

	spin_lock_irqsave(&getlock, flags);
	PktCnt = ioread32(pEip93RegBase + (PE_RD_COUNT >> 2)) & (BIT_10 - 1); //PE_RD_COUNT/4

	//don't wait for Crypto Engine in order to speed up!
	if(PktCnt == 0)
	{
		spin_unlock_irqrestore(&getlock, flags);
		return 0; //no result yet
	}
	
	if(resRingIdx == EIP93_RING_SIZE)
	{
		resRingIdx = 0;
	}	
	pRrd += (resRingIdx << 3); //resRingIdx*8 (a resDescp has 8 words!)

	while (1)
	{
		
		PktCnt = ioread32(pEip93RegBase + (PE_RD_COUNT >> 2)) & (BIT_10 - 1); //PE_RD_COUNT/4

		resDescp->peCrtlStat.word 	= pRrd[0];
		resDescp->userId		 	= pRrd[6];
		resDescp->peLength.word 	= pRrd[7];
		//the others are physical addresses, no need to be copied!
		done1 = resDescp->peCrtlStat.bits.peReady;
		done2 = resDescp->peLength.bits.peReady;
		err_sts = resDescp->peCrtlStat.bits.errStatus;
		resDescp->saAddr.phyAddr = pRrd[3];
		if ((done1 == 1) && (done2 == 1))
		{	
			if(unlikely(err_sts))
			{
				int cmdPktCnt = (ioread32(pEip93RegBase + (PE_CD_COUNT >> 2)) & (BIT_10 - 1));
				skb = (struct sk_buff *)resDescp->userId;
				addrCurrAdapter = (unsigned int *) &(skb->cb[36]);
				currAdapterPtr = (ipsecEip93Adapter_t *)(*addrCurrAdapter);
				printk("\n\n !PE Ring[%d] ErrCode=0x%x! status=%x rdn=%d cdn=%d encrypt=%d qlen=%d\n\n", resRingIdx, err_sts, ioread32(pEip93RegBase + (PE_CTRL_STAT >> 2)), PktCnt,\
						cmdPktCnt,currAdapterPtr->isEncryptOrDecrypt, currAdapterPtr->skbQueue.qlen);
				//for encryption/decryption case
				//if (resDescp->peCrtlStat.bits.hashFinal == 0x1)
				{
#if defined (MCRYPTO_DBG)
					if ((err_sts&0x1)==0x1)
					{	
						{
							int k;
							int offset, alloc_size;
							offset = mtkDMAAlign-(u32)(skb->data)%mtkDMAAlign;
							printk("ICV[[");
							for (k = 0; k < 12; k++)
								printk("%02X ",skb->data[resDescp->peLength.bits.length-12+k+offset]);
							printk("]]\n");	
						}
					}
#endif

					if ((resDescp->userId>>31)&0x1)
					{	
#if defined (BUFFER_MEMCPY)
						addrCurrAdapter = (unsigned int *) &(skb->cb[36]);
						currAdapterPtr = (ipsecEip93Adapter_t *)(*addrCurrAdapter);
						if (pRrd[2]!=pRrd[1])
						{
							int offset, alloc_size;	
							u8* pData =  *(unsigned int *)&(skb->cb[40]);
							offset = mtkDMAAlign-(u32)(skb->data)%mtkDMAAlign;
							alloc_size = skb->end-skb->head+sizeof(struct skb_shared_info)+offset;	
#if defined (SKB_HEAD_SHIFT)
#else						
							dma_unmap_single (NULL, pRrd[2], skb->len + currAdapterPtr->addedLen, PCI_DMA_FROMDEVICE);
							kfree(pData);	
#endif
						}
#endif
						kfree_skb(skb);
					}
					else
						printk("resDescp->userId = 0x%x\n", resDescp->userId);	
				}
				//else {

				//}	
					 
				retVal = -1;
				break;
			}
			skb = (struct sk_buff *)resDescp->userId;
#if defined (BUFFER_MEMCPY)
			if((skb!=NULL)&&(resDescp->peCrtlStat.bits.hashFinal == 0x1))
			{
				addrCurrAdapter = (unsigned int *) &(skb->cb[36]);
				currAdapterPtr = (ipsecEip93Adapter_t *)(*addrCurrAdapter);	
				if (pRrd[2]!=pRrd[1])	
				{	
#if defined (SKB_HEAD_SHIFT)
					int offset, alloc_size;
					offset = mtkDMAAlign-(u32)(skb->data)%mtkDMAAlign;
					copy_data_head(skb, offset);
#else					
					u8* pData =  *(unsigned int *)&(skb->cb[40]);
					dma_cache_sync(NULL, pData, skb->len + currAdapterPtr->addedLen, DMA_FROM_DEVICE);
					memcpy(skb->data, (u32)pData, resDescp->peLength.bits.length);
					dma_unmap_single (NULL, pRrd[2], skb->len + currAdapterPtr->addedLen, PCI_DMA_FROMDEVICE);			
					kfree(pData);
#endif
				}

			}
#endif
			retVal = 1;
			break; 
		}
		else
		{
			//if eip93 is done but the result is not ready yet, just reCkeckResult one more time!
			if (timeCnt++ > 10)
			{
				printk("\n !wait eip93's result for too long! Drop it! \n");
				printk("resRingIdx=%d\n",resRingIdx);
				//if (resDescp->peCrtlStat.bits.hashFinal == 0x1)
				{
					skb = (struct sk_buff *)resDescp->userId;
					if ((resDescp->userId>>31)&0x1)
					{
#if defined (BUFFER_MEMCPY)
						addrCurrAdapter = (unsigned int *) &(skb->cb[36]);
						currAdapterPtr = (ipsecEip93Adapter_t *)(*addrCurrAdapter);	
						if (pRrd[2]!=pRrd[1])
						{
							int offset, alloc_size;	
							u8* pData =  *(unsigned int *)&(skb->cb[40]);
							offset = mtkDMAAlign-(u32)(skb->data)%mtkDMAAlign;
							alloc_size = skb->end-skb->head+sizeof(struct skb_shared_info)+offset;	
#if defined (SKB_HEAD_SHIFT)
#else							
							dma_unmap_single (NULL, pRrd[2], skb->len + currAdapterPtr->addedLen, PCI_DMA_FROMDEVICE);
							kfree(pData);		
#endif
						}
#endif
						kfree_skb(skb);
					}
					else
						printk("resDescp->userId = 0x%x\n", resDescp->userId);		
				} 
			
				retVal = -1;
				break;
			}
		}
	} //end while(1)
	
	//clear the peCrtlStat of the currrent resRingDescp, in case eip93 can't put the current result in resRingDescp on time!
	pRrd[0] = 0;

	wmb();
	resRingIdx++;
	iowrite32(1, pEip93RegBase + (PE_RD_COUNT >> 2)); //PE_RD_COUNT/4
	spin_unlock_irqrestore(&getlock, flags);
	return retVal;
}



static bool mtk_eip93CmdResCnt_check(void)
{
	return (
		((ioread32(pEip93RegBase + (PE_CD_COUNT >> 2)) & (BIT_10 - 1)) < EIP93_RING_SIZE) &&
		((ioread32(pEip93RegBase + (PE_RD_COUNT >> 2)) & (BIT_10 - 1)) < (EIP93_RING_SIZE - EIP93_RING_BUFFER))
	);
}


/************************************************************************
*              P U B L I C     F U N C T I O N S
*************************************************************************
*/

// For interfacing with cryptoEngine
EXPORT_SYMBOL(mtk_packet_put);
EXPORT_SYMBOL(mtk_packet_get);
EXPORT_SYMBOL(mtk_eip93CmdResCnt_check);


/*
void  mtk_cryptoengine_init(void)
{
	printk("Mtk-Crypto-Engine : %s %s initializing...\n",__DATE__,__TIME__);
	spin_lock_init(&putlock);
	spin_lock_init(&getlock);
	write_c0_config7((read_c0_config7()|(1<<8)));
		
	//function pointer init
/*	ipsec_packet_put = mtk_packet_put;
	ipsec_packet_get = mtk_packet_get;
	ipsec_eip93CmdResCnt_check = mtk_eip93CmdResCnt_check;
	ipsec_preComputeIn_cmdDescp_set = mtk_preComputeIn_cmdDescp_set;
	ipsec_preComputeOut_cmdDescp_set = mtk_preComputeOut_cmdDescp_set;
	ipsec_cmdHandler_cmdDescp_set = mtk_cmdHandler_cmdDescp_set;
	ipsec_espNextHeader_set = mtk_espNextHeader_set;
	ipsec_espNextHeader_get = mtk_espNextHeader_get;
	ipsec_pktLength_get = mtk_pktLength_get;
	ipsec_eip93HashFinal_get = mtk_eip93HashFinal_get;
	ipsec_eip93UserId_get = mtk_eip93UserId_get;
	ipsec_addrsDigestPreCompute_free = mtk_addrsDigestPreCompute_free;
	ipsec_cmdHandler_free = mtk_cmdHandler_free;
	ipsec_hashDigests_get = mtk_hashDigests_get;
	ipsec_hashDigests_set = mtk_hashDigests_set;
	
	ipsec_espSeqNum_get = mtk_espSeqNum_get;
*
	//eip93 info init
	cmdRingIdx = ioread32(pEip93RegBase + (PE_RING_PNTR >> 2)) & (BIT_10-1); 
	resRingIdx = (ioread32(pEip93RegBase + (PE_RING_PNTR >> 2)) >>16) & (BIT_10-1);

	//eip93 interrupt mode init
	Adapter_Interrupt_ClearAndEnable(IRQ_RDR_THRESH_IRQ);
	Adapter_Interrupt_SetHandler(IRQ_RDR_THRESH_IRQ, mtk_interruptHandler_done);
	
	//EndianSwap Setting for C.L.'s new POF for fix no_word_alignment  (put right b4 kick CryptoEngine)
	iowrite32(0x00000700, pEip93RegBase + (PE_CONFIG >> 2));
	iowrite32(0x00e400e4, pEip93RegBase + (PE_ENDIAN_CONFIG >> 2));
}
*/

int copy_data_head(struct sk_buff *skb, int offset)
{
	unsigned int i;

	if (skb_shinfo(skb)->nr_frags > 0)
	{
		printk("skb %08X has frags\n",skb);
		return -1;
	}	
	for(i=(unsigned int)(skb->data-1);i>=(unsigned int) skb->head;i--) {

		*((unsigned char*)(i+offset)) = *((unsigned char*)(i));

    }

	skb->data += offset;

	/* {transport,network,mac}_header and tail are relative to skb->head */
	skb->tail	      += offset;
	skb->transport_header += offset;
	skb->network_header   += offset;
	if (skb_mac_header_was_set(skb))
		skb->mac_header += offset;
	/* Only adjust this if it actually is csum_start rather than csum */
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		skb->csum_start += 0;
	skb->cloned   = 0;
	skb->hdr_len  = 0;
	skb->nohdr    = 0;

	return 0;	
}

/*
int __init VDriver_Init(void)
{    
	// hook up kernel esp4/6_input/output functions

}


void __exit VDriver_Exit(void)
{
	// unhook up kernel esp4/6_input/output functions
}


MODULE_LICENSE("GPL");

module_init(VDriver_Init);
module_exit(VDriver_Exit);
*/
