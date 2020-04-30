
//#define DEBUG 1
#include "default.h"

#include "macvlist.h"

#define MACVENDOR_MIN_NELSON	(2)	/* Min distance between top and end for Nelson Search */

/*
 * Return a vendor string or an empty string "" by mac.
 */
const char *
MacVendor_by_mac(uint8_t *mac)
{
	uint64_t mac_id;
	char *vendor = "";

	/* Convert 6-byte hw mac address to ID that can be used for lookup */
	/* ID's for lookup ignore the last byte of the mac address to save space */
	mac_id = mac[4];
	mac_id |= (uint64_t)mac[3] << 8;
	mac_id |= (uint64_t)mac[2] << (8*2);
	mac_id |= (uint64_t)mac[1] << (8*3);
	mac_id |= (uint64_t)mac[0] << (8*4);

	//DEBUGF("Looking for %llx \n", mac_id);

	/* Perform a Newton Search */

	uint32_t top_loc = 0;
	uint32_t end_loc = sizeof macvendorlist / sizeof *macvendorlist - 1;
	uint64_t top_mid;
	uint64_t end_mid;
	uint32_t loc = 0;
	while (1)
	{
		//DEBUGF("top_loc %d, end_loc %d\n", top_loc, end_loc);
		if (top_loc >= sizeof macvendorlist / sizeof *macvendorlist - 1)
			break;

		/* Stop if there are just a few locations between top<->end and do sequential search */
		if (end_loc - top_loc + 1 < MACVENDOR_MIN_NELSON)
		{
			//DEBUGF("Narrowed it down to %d locations...\n", end_loc - top_loc + 1);
			break;
		}
		top_mid = macvendorlist[top_loc].macid;
		end_mid = macvendorlist[end_loc].macid;
		//DEBUGF("MICS %llx..%llx\n", top_mid, end_mid);
		if (top_mid > mac_id)
		{
			fprintf(stderr, "SHOULD NOT HAPPEN\n");
			break;
		}

		/* Make a guess where which location our value could be */
		uint64_t diff = end_mid - top_mid;
		uint64_t chunk_size = diff / (end_loc - top_loc);
		loc = (mac_id - top_mid) / chunk_size + top_loc;

		//DEBUGF("I think it's at location %u\n", loc);

		/* Check if we overshot and move end_loc up to our guessed location.
		 * Our guessed location becomes the new end_loc. Try again on this smaller group.
		 */
		if (macvendorlist[loc].macid > mac_id)
		{
			//DEBUGF("Overshot. %llx > %llx\n", macvendorlist[loc].macid, mac_id);
			end_loc = loc - 1;
			/* Can we recover from an overshot a bit better? */
			if (macvendorlist[top_loc + (end_loc - top_loc) / 2].macid < mac_id)
			{
				//DEBUGF("Recovering...\n");
				top_loc = top_loc + (end_loc - top_loc) / 2;
			}
			continue;
		}

		/* HERE: mac_id is somewhere between top_loc ... end_loc */
		/* If the next location has a mac that's larger than ours than the current
		 * location is the nearest hit.
		 */
		if (macvendorlist[loc + 1].macid > mac_id)
		{
			//DEBUGF("biggert. %llx > %llx\n", macvendorlist[loc+1].macid, mac_id);
			break;
		}
		/* Check if we guessed the same location and if so move up by 1...we are near..*/
		if (top_loc == loc)
			top_loc = loc + 1;
		else
			top_loc = loc;

		/* HERE: Our new chunk to search in... */

		/* Adjust the 'end' if it is far away... */
		if (macvendorlist[top_loc + (end_loc - top_loc)/2].macid > mac_id)
			end_loc = top_loc + (end_loc - top_loc)/2;
	}

	/* There can be duplicated in the list such as this one
	 * 00:1B:C5        IEEERegi        IEEE Registration Authority
	 * 00:1B:C5:00:00:00/36    Convergi        Converging Systems Inc.
	 * Check if the next immediately following is a better hit.
	 * Also doing sequential search here after Nelson search (small chunk left).
	 */
	int i;
	for (i = 0; i < MACVENDOR_MIN_NELSON; i++)
	{
		if (loc < sizeof macvendorlist / sizeof *macvendorlist - 1)
			break;
		if (macvendorlist[loc+1].macid > mac_id)
			break;
		loc++;
	}

	vendor = macvendorlist[loc].name;
	//DEBUGF("Vendor: %s\n", vendor);
	return vendor;
}


#if 0
int
main(int argc, char *argv[])
{

	//MacVendor_by_mac((uint8_t *)"\x00\x00\x01\x00\xab\xcd");
	MacVendor_by_mac((uint8_t *)"\xFC\xFF\xFF\xaa\xbb\xcc");
	//MacVendor_by_mac((uint8_t *)"\xF0\xB3\xD5\x67\x41\x11");

	for (int i = 0; i < sizeof macvendorlist / sizeof *macvendorlist - 1; i++)
	{
		uint8_t buf[6];
		uint64_t macid;
		const char *vendor;

		macid = macvendorlist[i].macid;
		/* Self test: Ignore duplicated..
		 */
		if (macid == macvendorlist[i+1].macid)
			continue;
		buf[5] = 0xab;
		buf[4] = macid >> 0*8;
		buf[3] = macid >> 1*8;
		buf[2] = macid >> 2*8;
		buf[1] = macid >> 3*8;
		buf[0] = macid >> 4*8;
		//HEXDUMP(buf, 6);

		vendor = MacVendor_by_mac(buf);
		if (macvendorlist[i].name != vendor)
			ERREXIT("NOT FOUND\n");

	}
	exit(0);
}
#endif
