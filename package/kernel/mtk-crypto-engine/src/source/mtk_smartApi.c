#include "mtk_armL0.h"
#include "mtk_internal.h"
#include "mtk_smartApi.h"

#include <asm/mach-ralink/rt_mmap.h>

// extern variables
extern int mtkDMAAlign;
extern unsigned int eip93_descr_size;
extern EIP93_Device_t* EIP93Device;
extern spinlock_t putlock, getlock;
extern unsigned int *pCmdRingBase, *pResRingBase; //uncached memory address


// Init functions
struct dma_pool *sadata_dmapool=NULL,*sastate_dmapool=NULL,*saarc4_dmapool=NULL;

bool InitDMAPoolsForSADataStateArc4(int sadatasize, int sastatesize, int saarc4size) {

	sadata_dmapool=dma_pool_create("eip93_sadata",NULL,sadatasize,mtkDMAAlign,0); // boundary 0
	if (sadata_dmapool==NULL) {
		printk("InitDMAPoolsForSADataStateArc4: unable to allocate dma pool for SAData (%d)",sadatasize); 			
		return false;
	}
	
	sastate_dmapool=dma_pool_create("eip93_sastate",NULL,sastatesize,mtkDMAAlign,0); // boundary 0
	if (sastate_dmapool==NULL) {
		printk("InitDMAPoolsForSADataStateArc4: unable to allocate dma pool for SAState (%d)",sastatesize); 			
		dma_pool_destroy(sadata_dmapool);
		return false;
	}


	// it is optional since we don't know for what it is needed for
	if (saarc4size!=0) {
		saarc4_dmapool=dma_pool_create("eip93_saarc4",NULL,saarc4size,mtkDMAAlign,0); // boundary 0
		if (saarc4_dmapool==NULL) {
			printk("InitDMAPoolsForSADataStateArc4: unable to allocate dma pool for SAData (%d)",saarc4size); 				dma_pool_destroy(sadata_dmapool);
			dma_pool_destroy(sastate_dmapool);
			return false;
		}
	}

	return true;
}



void UnInitDMAPoolsForSADataStateArc4(void) {
	if (sadata_dmapool!=NULL) {
		dma_pool_destroy(sadata_dmapool);
		printk("UnInitDMAPoolsForSADataStateArc4: destroyed dma pool for SAData"); 				
	}
	if (sastate_dmapool!=NULL) {
		dma_pool_destroy(sastate_dmapool);
		printk("UnInitDMAPoolsForSADataStateArc4: destroyed dma pool for SAState"); 				
	}
	if (saarc4_dmapool!=NULL) {
		dma_pool_destroy(saarc4_dmapool);
		printk("UnInitDMAPoolsForSADataStateArc4: destroyed dma pool for SAARC4"); 				
	}
}


// Dma functions

// This buffer is consistent, i.e. all writes from cpu are written back to memory and all write from a device invalidate cpu cache on the
// address automatically. It has the implicit direction DMA_BIDIRECTIONAL. They do not need any sync operation.
DmaBuffer *DmaBuffer_Alloc(size_t size) {
	DmaBuffer *buf=(DmaBuffer *) kmalloc(sizeof(DmaBuffer),GFP_KERNEL);
	if (buf==NULL)
		return NULL;

	buf->size=size;
	buf->allocType=COHERENT;
	buf->kernelAddr = dma_zalloc_coherent(NULL, size, &buf->dmaAddr, GFP_KERNEL);
	if (buf->kernelAddr==NULL) {
		kfree (buf);
		return NULL;
	}

	return buf;
}


// This buffer is consistent, i.e. all writes from cpu are written back to memory and all write from a device invalidate cpu cache on the
// address automatically. It has the implicit direction DMA_BIDIRECTIONAL. They do not need any sync operation.
DmaBuffer *DmaBuffer_AllocPool(struct dma_pool *pool, int size) {

	DmaBuffer *buf=(DmaBuffer *) kmalloc(sizeof(DmaBuffer),GFP_KERNEL);
	if (buf==NULL)
		return NULL;

	buf->size=size;
	buf->allocType=POOLED;
	buf->kernelAddr = dma_pool_alloc(pool, GFP_KERNEL|__GFP_ZERO,&buf->dmaAddr);  // __GFP_ZERO like zalloc which is only supported in latest kernel
	if (buf->kernelAddr==NULL) {
		kfree (buf);
		return NULL;
	}
	buf->allocPool=pool;
	
	return buf;
}


// This buffer is inconsistent, i.e. all writes from cpu are not written back to memory and all writes from a device do not invalidate cpu 
// cache on the address automatically. You must specify a map direction . They need a sync operation.
DmaBuffer *DmaBuffer_Map(void *kaddr,int size,enum dma_data_direction direction) {
	DmaBuffer *buf=(DmaBuffer *) kmalloc(sizeof(DmaBuffer),GFP_KERNEL);
	if (buf==NULL)
		return NULL;

	buf->size=size;
	buf->allocType=MAPPED;
	buf->mapDirection=direction;
	buf->kernelAddr=kaddr;
	buf->dmaAddr = dma_map_single(NULL, kaddr, size, direction);
	if (dma_mapping_error(NULL,buf->dmaAddr)) {
		kfree (buf);
		return NULL;
	}
	
	return buf;
}


void DmaBuffer_Free (DmaBuffer * buf) {
	if (buf==NULL)
		return;

	switch (buf->allocType) {
		case MAPPED:
			// this buffer could be already been deallocated for perfomance boost		
			if (buf->dmaAddr!=NULL) {
				dma_unmap_single(NULL,buf->dmaAddr,buf->size,buf->mapDirection);
				buf->dmaAddr=NULL;
			}
		break;

		case COHERENT:
			dma_free_coherent(NULL,buf->size,buf->kernelAddr,buf->dmaAddr);
		break;

		case POOLED:
			dma_pool_free(buf->allocPool,buf->kernelAddr,buf->dmaAddr);
		break;
	}
}



// Packet functions

EIP93Packet *EIP93_AllocPacket(EIP93_ResultCallback cbk) {

	EIP93Packet *packet=(EIP93Packet *) kmalloc(sizeof(EIP93Packet),GFP_KERNEL);
	if (packet==NULL)
		return NULL;

	packet->Callback=cbk;
	// inner allocs could fail but in that case there is no memory to do anything, so it's acceptable a core dump
	packet->SAData=DmaBuffer_AllocPool(sadata_dmapool,128);
	packet->SAState=DmaBuffer_AllocPool(sastate_dmapool,56);
	if (saarc4_dmapool!=NULL)
		packet->SAArc4=DmaBuffer_AllocPool(saarc4_dmapool,56);	  // it should be the same size of sastate (to check)	

	return packet;
}


EIP93Packet **EIP93_AllocPackets(int numPackets,EIP93_ResultCallback cbk) {
	int i;
	EIP93Packet **arrPackets=(EIP93Packet **) kmalloc(numPackets*sizeof(EIP93Packet *),GFP_KERNEL);

	if (arrPackets==NULL)
		return NULL;

	// inner allocs could fail but in that case there is no memory to do anything, so it's acceptable a core dump
	for (i=0;i<numPackets;i++)
		arrPackets[i]=EIP93_AllocPacket(cbk);

	return arrPackets;
}


void EIP93_FreePacket(EIP93Packet *packet) {
	DmaBuffer_Free(packet->SrcData);
	DmaBuffer_Free(packet->DstData);
	DmaBuffer_Free(packet->SAData);
	DmaBuffer_Free(packet->SAState);
	DmaBuffer_Free(packet->SAArc4);
	kfree(packet);
}



void DumpBinary(void *addr, int len, int longperrow) {
	int i;
	unsigned int *ad=(unsigned int *) addr;

	for (i=0;i<len/4;i++) {
	        printk("0x%08x\t", *(ad+i));
        	if (i%(longperrow+1)==longperrow) printk("\n");
	}
}


void DumpDMA(DmaBuffer *buf, int maxlen,int longperrow, char *bufname) {
	printk("%d-byte %s buffer from 0x%p (dma 0x%p):\n", buf->size, bufname,buf->kernelAddr,buf->dmaAddr);
	DumpBinary(buf->kernelAddr,MIN(buf->size,maxlen),longperrow);
}

void EIP93_DumpPacket(EIP93Packet *packet, char *methodname) {
	printk("%s: Dump packet\n",methodname);
	printk("ControlWord:0x%08x\n", packet->ControlStat.word); 

	if (packet->SrcData!=NULL)
		DumpDMA(packet->SrcData,128,5,"SrcData");

	DumpDMA(packet->SAData,128,5,"SAData");

	DumpDMA(packet->SAState,56,5,"SAState");

	if (packet->SAArc4!=NULL)
		DumpDMA(packet->SAArc4,56,5,"SAArc4");

	printk("Userdata:0x%08x\n", packet->Userdata); 
	printk("Length:0x%08x Bypass:0x%08x\n", packet->Length,packet->BypassWords); 
}



void EIP93_DumpRing (unsigned int *pCrd,int index,char *methodname) {
	printk("%s: Dump Ring %d at 0x%p\n", methodname,index,&pCrd[0]); 
	printk("[0]:0x%08x\n", pCrd[0]); 
	printk("[1]:0x%08x\n", pCrd[1]); 
	printk("[2]:0x%08x\n", pCrd[2]); 
	printk("[3]:0x%08x\n", pCrd[3]); 
	printk("[4]:0x%08x\n", pCrd[4]); 
	printk("[5]:0x%08x\n", pCrd[5]); 
	printk("[6]:0x%08x\n", pCrd[6]); 
	printk("[7]:0x%08x\n", pCrd[7]); 
}


void EIP93_FreePackets(EIP93Packet **packets, int num) {
	int i;

	for (i=0;i<num;i++)
		EIP93_FreePacket(packets[i]);
}



int EIP93_ARM_Packet_Put(EIP93Packet *packet) {
	uint32_t pckToProcess;
	uint16_t ringOff,ringNextOff,ringSize,insertedpck=0;
	int i;

	spin_lock(&putlock);

	printk("EIP93_ARM_Packet_Put: EIP93Device %x\n",EIP93Device);

	EIP93_Read32_PE_CD_COUNT(EIP93Device,&pckToProcess);
	EIP93_Read32_PE_RING_SIZE(EIP93Device,&ringOff,&ringSize);
	ringNextOff=(ringOff==ringSize)?0:ringOff;
	
	printk("EIP93_ARM_Packet_Put: PckToProcess %d Next Offset %d Size %d\n",pckToProcess,ringNextOff,ringSize);

	if (pckToProcess<ringSize) {
		unsigned int *pCrd = pCmdRingBase+(ringNextOff*eip93_descr_size);  

		unsigned int slen=((packet->SrcData!=NULL)?packet->SrcData->size:0) &(MASK_20_BITS); // source packets can't exceed 1MB

		packet->ControlStat.bits.hostReady=1; // Host Ready bit is set 

		// set len & bypass into Length field
		packet->Length.bits.byPass=packet->BypassWords;
		packet->Length.bits.length=slen;
		packet->Length.bits.hostReady=1; // Host Ready bit is set, 

		// two conventions:
		// if there is no dest we pass again source as dest
		// if there is no SAArc4 we pass SAState as SAArc4
		pCrd[0] = packet->ControlStat.word;
		pCrd[1] = (packet->SrcData!=NULL)?packet->SrcData->dmaAddr:NULL; // we must pass dmaAddr to the CE
		pCrd[2] = (packet->DstData!=NULL)?packet->DstData->dmaAddr:pCrd[1]; // we must pass dmaAddr to the CE
		pCrd[3] = packet->SAData->dmaAddr;
		pCrd[4] = packet->SAState->dmaAddr;
		pCrd[5] = (packet->SAArc4!=NULL)?packet->SAArc4->dmaAddr:pCrd[4];
		// we need to pass the whole structure to userdata (containing custom userdata) since the result contain only dma 
		// addresses which are useless for accessing destination data
		pCrd[6] = (unsigned int) packet;  
		pCrd[7] = packet->Length.word; 
		// potential padding
		for(i = 8; i < eip93_descr_size; i++) 
			pCrd[8]=0;

		// a device has written some data and cpu has to read it call dma_cache_inv invalidate only
		// cpu has written some data and the device has to read it call dma_cache_wback writeback only
		// the region will be written by both call dma_cache_wback_inv writeback and invalidate
		// it seems that linux provides a general function for this yet it seem not to be working on some archicture..
		// writeback cache otherwise device will get bad data (might remain only written in cache), 3 cases:
//		if (slen>0) 
//			dma_sync_single_for_device(NULL, packet->SrcData->dmaAddr, packet->SrcData->size,DMA_TO_DEVICE);

		// flush also ring memory written with the send packet
		// no, it is not needed ring memory is allocated through dma_alloc_coherent
//		dma_sync_single_for_device(NULL, Adapter_EIP93_CmdRing_Handle+ringNextOff*eip93_descr_size*4, 1*eip93_descr_size*4,DMA_TO_DEVICE);

		// SAState, SAData and SAArc4 are coeherent dma mappings (they are dma pools) so they are automatically synchronized

		// Dump packet
		EIP93_DumpPacket(packet,"EIP93_ARM_Packet_Put");
		EIP93_DumpRing(pCrd,ringNextOff,"EIP93_ARM_Packet_Put");

		// Tell CE that a new packet is ready
		insertedpck=1; 		// 1 è il numero di pacchetto accodati
		EIP93_Write32_PE_CD_COUNT(EIP93Device,insertedpck);
	}

	spin_unlock(&putlock);

	return insertedpck;
}



EIP93ResultPacket *EIP93_ARM_Packet_Get(void) {
	uint32_t pckProcessed;
	uint16_t ringOff,ringNextOff,ringSize,insertedpck=0,nextRd=-1,nextCd=-1;
	unsigned int done1,done2,err;

	EIP93ResultPacket *packet=NULL;

	spin_lock(&getlock);

	// Read how many results are there
	EIP93_Read32_PE_RD_COUNT(EIP93Device,&pckProcessed);
	EIP93_Read32_PE_RING_SIZE(EIP93Device,&ringOff,&ringSize);
	EIP93_Read32_PE_RING_PNTR(EIP93Device,&nextCd,&nextRd);

	ringNextOff=(ringOff==ringSize)?0:ringOff;

	printk("EIP93_ARM_Packet_Get: ResultToGet %d Next Get Offset %d Size %d Next Put Off %d\n",pckProcessed,nextRd,ringSize,nextCd);

	if (pckProcessed>0 && (packet=(EIP93ResultPacket *) kmalloc(sizeof(EIP93ResultPacket),GFP_KERNEL)!=NULL)) {
		unsigned int *pCrd = pResRingBase+(nextRd*eip93_descr_size);  			

		packet->ControlStat.word=pCrd[0];
		packet->Length.word=pCrd[7];
		packet->InputPacket=(EIP93Packet *) pCrd[6];

		done1 = packet->ControlStat.bits.peReady;
		done2 = packet->Length.bits.peReady;
		err = packet->ControlStat.bits.errStatus;

		// Dump ring
		EIP93_DumpRing(pCrd,nextRd,"EIP93_ARM_Packet_Get");

		if ((done1 == 1) && (done2 == 1))
		{	
			printk("EIP93_ARM_Packet_Get[%d]: Received Packet ControlWord %d DstBytes %d BypassDst %d Done1 %d Done2 %d Err %d\n",nextRd,packet->ControlStat.word,packet->Length.bits.length,packet->Length.bits.byPass,done1,done2,err);

			// only for mapped we invalidate the destination cache so that the caller can directly access kernel memory to read the resul without worrying about DMA issue 
			if (packet->InputPacket->DstData!=NULL && packet->InputPacket->DstData->allocType==MAPPED)
				DmaBuffer_Free(packet->InputPacket->DstData);

			// if there is an error log it (bad packet see what to log)
			if (unlikely(packet->ControlStat.bits.errStatus)) {
				uint32_t status = EIP93_Read32(EIP93Device, EIP93_REG_PE_CTRL_STAT);
				printk("EIP93_ARM_Packet_Get[%d]: Packet ERROR ext. status %d\n",nextRd,status);
			}
			else 
				DumpDMA(packet->InputPacket->DstData,128,5,"DstData");

			// Tell CE that the packet has been read
			EIP93_Write32_PE_RD_COUNT(EIP93Device,(uint32_t)1);
		}
		else {
			printk("EIP93_ARM_Packet_Get[%d]: Still processing packet ControlWord %d DstBytes %d BypassDst %d Done1 %d Done2 %d Err %d\n",nextRd,packet->ControlStat.word,packet->Length.bits.length,packet->Length.bits.byPass,done1,done2,err);
			// Retry ?!? The ce is drunk and is sending spurious interrupts...let's hope it will send another when it has really finished
			// Abort ?!? Write 0 in pCrd[0]
			kfree(packet);
			packet=NULL;			
		}
	}

	spin_unlock(&getlock);

	return packet;
}



// Ipsec functions


void IPSEC_DumpState (IPSEC_SAState *s) {
	printk("16-byte StateIV from 0x%p:\n", s->stateIv);
	DumpBinary(s->stateIv,16,5);

	printk("8-byte StateByteCnt from 0x%p:\n", s->stateByteCnt);
	DumpBinary(s->stateByteCnt,8,5);

	printk("32-byte StateIDigest from 0x%p:\n", s->stateIDigest);
	DumpBinary(s->stateIDigest,32,5);
}


