#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "e1000_dev.h"
#include "net.h"

#define TX_RING_SIZE 16
static struct tx_desc tx_ring[TX_RING_SIZE] __attribute__((aligned(16)));
static struct mbuf *tx_mbufs[TX_RING_SIZE];

#define RX_RING_SIZE 16
static struct rx_desc rx_ring[RX_RING_SIZE] __attribute__((aligned(16)));
static struct mbuf *rx_mbufs[RX_RING_SIZE];

// remember where the e1000's registers live.
static volatile uint32 *regs;

struct spinlock e1000_lock;

// called by pci_init().
// xregs is the memory address at which the
// e1000's registers are mapped.
void
e1000_init(uint32 *xregs)
{
  int i;

  initlock(&e1000_lock, "e1000");

  regs = xregs;

  // Reset the device
  regs[E1000_IMS] = 0; // disable interrupts
  regs[E1000_CTL] |= E1000_CTL_RST;
  regs[E1000_IMS] = 0; // redisable interrupts
  __sync_synchronize();

  // [E1000 14.5] Transmit initialization
  memset(tx_ring, 0, sizeof(tx_ring));
  for (i = 0; i < TX_RING_SIZE; i++) {
    tx_ring[i].status = E1000_TXD_STAT_DD;
    tx_mbufs[i] = 0;
  }
  regs[E1000_TDBAL] = (uint64) tx_ring;
  if(sizeof(tx_ring) % 128 != 0)
    panic("e1000");
  regs[E1000_TDLEN] = sizeof(tx_ring);
  regs[E1000_TDH] = regs[E1000_TDT] = 0;
  
  // [E1000 14.4] Receive initialization
  memset(rx_ring, 0, sizeof(rx_ring));
  for (i = 0; i < RX_RING_SIZE; i++) {
    rx_mbufs[i] = mbufalloc(0);
    if (!rx_mbufs[i])
      panic("e1000");
    rx_ring[i].addr = (uint64) rx_mbufs[i]->head;
  }
  regs[E1000_RDBAL] = (uint64) rx_ring;
  if(sizeof(rx_ring) % 128 != 0)
    panic("e1000");
  regs[E1000_RDH] = 0;
  regs[E1000_RDT] = RX_RING_SIZE - 1;
  regs[E1000_RDLEN] = sizeof(rx_ring);

  // filter by qemu's MAC address, 52:54:00:12:34:56
  regs[E1000_RA] = 0x12005452;
  regs[E1000_RA+1] = 0x5634 | (1<<31);
  // multicast table
  for (int i = 0; i < 4096/32; i++)
    regs[E1000_MTA + i] = 0;

  // transmitter control bits.
  regs[E1000_TCTL] = E1000_TCTL_EN |  // enable
    E1000_TCTL_PSP |                  // pad short packets
    (0x10 << E1000_TCTL_CT_SHIFT) |   // collision stuff
    (0x40 << E1000_TCTL_COLD_SHIFT);
  regs[E1000_TIPG] = 10 | (8<<10) | (6<<20); // inter-pkt gap

  // receiver control bits.
  regs[E1000_RCTL] = E1000_RCTL_EN | // enable receiver
    E1000_RCTL_BAM |                 // enable broadcast
    E1000_RCTL_SZ_2048 |             // 2048-byte rx buffers
    E1000_RCTL_SECRC;                // strip CRC
  
  // ask e1000 for receive interrupts.
  regs[E1000_RDTR] = 0; // interrupt after every received packet (no timer)
  regs[E1000_RADV] = 0; // interrupt after every packet (no timer)
  regs[E1000_IMS] = (1 << 7); // RXDW -- Receiver Descriptor Write Back
}

int
e1000_transmit(struct mbuf *m)
{
    //
    // Your code here.
    //
    // the mbuf contains an ethernet frame; program it into
    // the TX descriptor ring so that the e1000 sends it. Stash
    // a pointer so that it can be freed after sending.
    //
    // Logging entry point of the transmit function.
    acquire(&e1000_lock); // Lock to ensure exclusive access to the transmit resources.

    // Retrieve the current position in the transmit descriptor ring.
    int pos = regs[E1000_TDT];

    // Check if the transmit descriptor is ready for reuse.
    // If not, the previous packet hasn't finished sending; return an error.
    if ((tx_ring[pos].status & E1000_TXD_STAT_DD) == 0) {
        release(&e1000_lock); // Release the lock before returning.
        return -1;
    }

    // Free the previously transmitted buffer, if it exists, to avoid memory leaks.
    struct mbuf *b = tx_mbufs[pos];
    if (b)
        mbuffree(b); // Free the memory buffer.

    // Assign the new packet's buffer address and length to the descriptor.
    tx_ring[pos].addr = (uint64) m->head;
    tx_ring[pos].length = (uint64) m->len;

    // Set command flags indicating end of packet and report status.
    tx_ring[pos].cmd |= E1000_TXD_CMD_EOP; // End of packet.
    tx_ring[pos].cmd |= E1000_TXD_CMD_RS; // Report status.

    // Store the pointer to the new packet buffer for later retrieval and freeing.
    tx_mbufs[pos] = m;

    // Update the transmit descriptor tail to the next position, wrapping around the ring buffer.
    regs[E1000_TDT] = (pos + 1) % TX_RING_SIZE;

    release(&e1000_lock); // Unlock after the transmit descriptor is updated.
    return 0; // Return success.
}


static void
e1000_recv(void)
{
  //
  // Your code here.
  //
  // Check for packets that have arrived from the e1000
  // Create and deliver an mbuf for each packet (using net_rx()).
  //
// Acquire the lock on the e1000 network interface to ensure exclusive access
  acquire(&e1000_lock);

  // Calculate the current position in the receive descriptor ring
  int cur = (regs[E1000_RDT]+1) % RX_RING_SIZE;

  // Continuously check if a new packet has been received
  while ((rx_ring[cur].status & E1000_RXD_STAT_DD) != 0) {
      // If E1000_RXD_STAT_DD bit is set, a new packet is available at the current index

      // Retrieve the length of the received packet from the descriptor
      int len = rx_ring[cur].length;

      // Update the associated memory buffer's (mbuf) length to match the received packet's length
      mbufput(rx_mbufs[cur], len);

      // Release the lock before passing the packet up the network stack to avoid holding the lock during potentially long operations
      release(&e1000_lock);

      // Deliver the packet to the network protocol layer
      net_rx(rx_mbufs[cur]);

      // Reacquire the lock to manipulate hardware registers and memory structures again
      acquire(&e1000_lock);

      // Allocate a new mbuf for the descriptor since the previous mbuf is now with the network stack
      rx_mbufs[cur] = mbufalloc(0);

      // Update the descriptor with the new mbuf's head pointer
      rx_ring[cur].addr = (uint64) rx_mbufs[cur]->head;

      // Clear the descriptor’s status bits to indicate it's ready for new data
      rx_ring[cur].status = 0;

      // Update the E1000_RDT register to the current position, effectively moving to the next descriptor
      regs[E1000_RDT] = cur;

      // Calculate the next position in the receive ring
      cur = (regs[E1000_RDT]+1) % RX_RING_SIZE;
  }
  // Release the lock after finishing processing all available packets
  release(&e1000_lock);

}

void
e1000_intr(void)
{
  // tell the e1000 we've seen this interrupt;
  // without this the e1000 won't raise any
  // further interrupts.
  regs[E1000_ICR] = 0xffffffff;

  e1000_recv();
}
