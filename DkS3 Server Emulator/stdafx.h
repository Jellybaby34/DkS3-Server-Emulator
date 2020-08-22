#ifndef STDAFX_HEADER_FILE
#define STDAFX_HEADER_FILE

#include <threadpool.h>
extern thread_pool threadPool;

// Packet header formats used to login and auth
#pragma pack(push)
#pragma pack(1)
typedef struct loginclientpacketheader_t {
	short packetLengthType1; // Total packet length - 2 in big endian
	short sentPacketsCounter; // Counter of total number of packets sent ?big endian
	short unknown1; // Always 0x00 0x00
	unsigned int packetLengthType2A; // Total packet length - 14 in big endian
	unsigned int packetLengthType2B; // Total packet length - 14 in big endian
	unsigned int unknown2; // Always 0x0C in big endian
	unsigned int unknown3; // An unknown constant that varies but isn't unique enough to be an ID. Big endian
	unsigned int receivedCounter; // Counter of packets sent this session. Little endian. Used in replies
} loginclientpacketheader_t;

typedef struct loginserverpacketheader_t {
	short packetlengthtype1; // Total packet length - 2 in big endian
	short sentpacketscounter; // Counter of total number of packets sent ?big endian
	short unknown1; // Always 0x00 0x00
	unsigned int packetlengthtype2A; // Total packet length - 14 in big endian
	unsigned int packetlengthtype2B; // Total packet length - 14 in big endian
	unsigned int unknown2; // Always 0x0C in big endian
	unsigned int unknown3; // An unknown constant that varies but isn't unique enough to be an ID. Big endian
	unsigned int receivedcounter; // Counter of packets sent this session. Little endian. Used in replies
	unsigned int unknown4; // Always 0x00 0x00 0x00 0x00
	unsigned int unknown5; // Always 0x00 0x00 0x00 0x01 (0x01 in big endian?)
	unsigned int unknown6; // Always 0x00 0x00 0x00 0x00
	unsigned int unknown7; // Always 0x00 0x00 0x00 0x00
} loginserverpacketheader_t;
#pragma pack(pop)


#endif