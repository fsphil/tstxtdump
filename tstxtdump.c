/* tstxtdump                                                             */
/*=======================================================================*/
/* Copyright 2020 Philip Heron <phil@sanslogic.co.uk>                    */
/*                                                                       */
/* This program is free software: you can redistribute it and/or modify  */
/* it under the terms of the GNU General Public License as published by  */
/* the Free Software Foundation, either version 3 of the License, or     */
/* (at your option) any later version.                                   */
/*                                                                       */
/* This program is distributed in the hope that it will be useful,       */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/* GNU General Public License for more details.                          */
/*                                                                       */
/* You should have received a copy of the GNU General Public License     */
/* along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

FILE *fout = NULL;
int verbose = 0;
int olines = 0;

static uint8_t _rev8(uint8_t b)
{
	b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
	b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
	b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
	return(b);
}

static void _parse_pes(const uint8_t *pes, size_t pes_len)
{
	const uint8_t *data;
	size_t data_len;
	
	while(pes_len)
	{
		if(verbose)
		{
			fprintf(stderr, " Packet start code prefix: 0x%02X%02X%02X\n", pes[0], pes[1], pes[2]);
			fprintf(stderr, "                Stream id: 0x%02X\n", pes[3]);
			fprintf(stderr, "        PES Packet length: %d\n", (pes[4] << 8) | pes[5]);
			
			fprintf(stderr, "              Marker bits: %d\n", (pes[6] >> 6) & 3);
			fprintf(stderr, "       Scrambling control: %d\n", (pes[6] >> 4) & 3);
			fprintf(stderr, "                 Priority: %d\n", (pes[6] >> 3) & 1);
			fprintf(stderr, " Data alignment indicator: %d\n", (pes[6] >> 2) & 1);
			fprintf(stderr, "                Copyright: %d\n", (pes[6] >> 1) & 1);
			fprintf(stderr, "         Original or Copy: %d\n", (pes[6] >> 0) & 1);
			fprintf(stderr, "        PTS DTS indicator: %d\n", (pes[7] >> 6) & 3);
			fprintf(stderr, "                ESCR flag: %d\n", (pes[7] >> 5) & 1);
			fprintf(stderr, "             ES rate flag: %d\n", (pes[7] >> 4) & 1);
			fprintf(stderr, "      DSM trick mode flag: %d\n", (pes[7] >> 3) & 1);
			fprintf(stderr, "Additional copy info flag: %d\n", (pes[7] >> 2) & 1);
			fprintf(stderr, "                 CRC flag: %d\n", (pes[7] >> 1) & 1);
			fprintf(stderr, "           extension flag: %d\n", (pes[7] >> 0) & 1);
			fprintf(stderr, "        PES header length: %d\n", pes[8]);
		}
		
		/* Validate the start code */
		if(pes[0] != 0x00 || pes[1] != 0x00 || pes[2] != 0x01)
		{
			fprintf(stderr, "Invalid Packet start code prefix 0x%02X%02X%02X - skipping PES packet\n", pes[0], pes[1], pes[2]);
			return;
		}
		
		/* Validate the stream ID */
		if(pes[3] != 0xBD)
		{
			fprintf(stderr, "Invalid Stream id 0x%02X - skipping PES packet\n", pes[3]);
			return;
		}
		
		data = &pes[8 + pes[8] + 1];
		data_len = ((pes[4] << 8) | pes[5]) - pes[8] - 3;
		
		if(verbose)
		{
			fprintf(stderr, "data_len = %ld\n", data_len);
			fprintf(stderr, "data_identifier: %02X\n", data[0]);
		}
		
		/* Validate the length */
		if(data_len > pes_len)
		{
			fprintf(stderr, "Invalid PES Packet length: %ld\n", data_len);
			return;
		}
		
		data_len -= 1;
		data += 1;
		
		while(data_len >= 46)
		{
			int j;
			
			if(verbose)
			{
				//fprintf(stderr, "(%ld)\n", data_len);
				fprintf(stderr, "               data_unit_id: %d\n", data[0]);
				fprintf(stderr, "           data_unit_length: %d\n", data[1]);
				fprintf(stderr, "        reserved_future_use: %d\n", (data[2] >> 6) & 3);
				fprintf(stderr, "               field_parity: %d\n", (data[2] >> 5) & 1);
				fprintf(stderr, "                line_offset: 0x%02X\n", data[2] & 0x1F);
				fprintf(stderr, "               framing_code: %d\n", data[3]);
				fprintf(stderr, "magazine_and_packet_address: %02X%02X\n", data[4], data[5]);
				fprintf(stderr, "                       data: '");
				for(j = 0; j < 40; j++)
				{
					fprintf(stderr, "%c", _rev8(data[6 + j]) & 0x7F);
				}
				fprintf(stderr, "'\n");
			}
			
			if(data[0] == 0x02 || data[0] == 0x03)
			{
				uint8_t rdata[42];
				
				/* Reverse the bytes for output */
				for(j = 0; j < 42; j++)
				{
					rdata[j] = _rev8(data[4 + j]);
				}
				
				fwrite(rdata, 42, 1, fout);
				olines++;
			}
			
			data_len -= data[1] + 2;
			data += data[1] + 2;
		}
		
		pes_len -= ((pes[4] << 8) | pes[5]) + 6;
		pes += ((pes[4] << 8) | pes[5]) + 6;
	}
}

static void _print_usage(void)
{
	fprintf(stderr,
		"Usage: tstxtdump -p <pid> [-v] [-S <bytes>] [-P <bytes] <in.ts> <out.t42>\n"
		"\n"
	        "  -p, --pid <number>             Select which PID to dump. Required.\n"
	        "  -S, --skip <number>            Number of bytes to skip at the beginning of\n"
		"                                 the file. Default: 0\n"
		"  -P, --pad <number>             Number of bytes to skip after each packet. A\n"
		"                                 negative value enables the header search.\n"
		"                                 Defaut: -1\n"
		"  -v, --verbose                  Enable verbose output.\n"
	);
}

int main(int argc, char *argv[])
{
	FILE *fin;
	uint8_t pkt[188], *payload;
	uint8_t payload_len;
	uint8_t counter = 0xFF;
	uint8_t pes[1024 * 4];
	uint16_t pid = 0;
	int skip = 0;
	int pad = -1;
	ssize_t pes_len = -1;
	int c;
	int option_index;
	static struct option long_options[] = {
		{ "pid",     required_argument, 0, 'p' },
		{ "skip",    required_argument, 0, 'S' },
		{ "pad",     required_argument, 0, 'P' },
		{ "verbose", no_argument,       0, 'v' },
		{ 0,         0,                 0,  0  }
	};
	
	opterr = 0;
	while((c = getopt_long(argc, argv, "p:S:P:v", long_options, &option_index)) != -1)
	{
		switch(c)
		{
		case 'p': /* -p, --pid <number> */
			pid = strtol(optarg, NULL, 0);
			break;
		
		case 'S': /* -S, --skip <bytes> */
			skip = strtol(optarg, NULL, 0);
			break;
		
		case 'P': /* -P, --pad <bytes> */
			pad = strtol(optarg, NULL, 0);
			break;
		
		case 'v': /* -v, --verbose */
			verbose = 1;
			break;
		
		case '?':
			_print_usage();
			return(0);
		}
	}
	
	if(argc != optind + 2)
	{
		_print_usage();
		return(-1);
	}
	
	if(pid == 0 || pid >= 0x2000)
	{
		fprintf(stderr, "Invalid PID 0x%X\n", pid);
		return(-1);
	}
	
	fprintf(stderr, "Dumping '%s' (PID 0x%X) > '%s'\n", argv[optind + 0], pid, argv[optind + 1]);
	
	fin = fopen(argv[optind + 0], "rb");
	if(!fin)
	{
		perror(argv[optind + 0]);
		return(-1);
	}
	
	fout = fopen(argv[optind + 1], "wb");
	if(!fout)
	{
		perror(argv[optind + 1]);
		fclose(fin);
		return(-1);
	}
	
	fseek(fin, skip, SEEK_CUR);
	
	while(fread(pkt, 188, 1, fin) == 1)
	{
		if(pkt[0] != 0x47)
		{
			if(pad < 0)
			{
				int i;
				
				c = 0;
				
				do
				{
					for(i = 0; i < 188; i++)
					{
						if(pkt[i] == 0x47) break;
					}
					
					c += i;
					memmove(pkt, &pkt[i], 188 - i);
					fread(&pkt[188 - i], i, 1, fin);
				}
				while(i == 188);

				if(verbose)
				{
					fprintf(stderr, "Skipped %d bytes\n", c);
				}
			}
			else
			{
				fprintf(stderr, "Bad TS header\n");
				fseek(fin, pad, SEEK_CUR);
				continue;
			}
		}
		
		/* Skip PIDs we don't need */
		if((((pkt[1] << 8) | pkt[2]) & 0x1FFF) != pid)
		{
			if(pad > 0)
			{
				fseek(fin, pad, SEEK_CUR);
			}
			continue;
		}
		
		if(counter != 0xFF && counter != (pkt[3] & 0x0F))
		{
			fprintf(stderr, "Continuity counter interruption %d != %d\n", pkt[3] & 0x0F, counter);
			pes_len = -1;
		}
		
		if(verbose)
		{
			/* Dump TS header */
			fprintf(stderr, "    Transport error indicator (TEI): %d\n", (pkt[1] >> 7) & 1);
			fprintf(stderr, "Payload unit start indicator (PUSI): %d\n", (pkt[1] >> 6) & 1);
			fprintf(stderr, "                 Transport priority: %d\n", (pkt[1] >> 5) & 1);
			fprintf(stderr, "                                PID: %d\n", ((pkt[1] << 8) | pkt[2]) & 0x1FFF);
			fprintf(stderr, " Transport scrambling control (TSC): %d\n", (pkt[3] >> 6) & 3);
			fprintf(stderr, "           Adaptation field control: %d\n", (pkt[3] >> 4) & 3);
			fprintf(stderr, "                 Continuity counter: %d\n", pkt[3] & 0x0F);
			fprintf(stderr, "---------------------------------------\n");
		}
		
		payload = &pkt[4];
		payload_len = 188 - 4;
		
		if((pkt[3] >> 5) & 1)
		{
			if(verbose)
			{
				/* Dump adaptation field */
				fprintf(stderr, "             Adaptation field length: %d\n", payload[0]);
				fprintf(stderr, "             Discontinuity indicator: %d\n", (payload[1] >> 7) & 1);
				fprintf(stderr, "             Random access indicator: %d\n", (payload[1] >> 6) & 1);
				fprintf(stderr, "Elementary stream priority indicator: %d\n", (payload[1] >> 5) & 1);
				fprintf(stderr, "                            PCR flag: %d\n", (payload[1] >> 4) & 1);
				fprintf(stderr, "                           OPCR flag: %d\n", (payload[1] >> 3) & 1);
				fprintf(stderr, "                 Splicing point flag: %d\n", (payload[1] >> 2) & 1);
				fprintf(stderr, "         Transport private data flag: %d\n", (payload[1] >> 1) & 1);
				fprintf(stderr, "     Adaptation field extension flag: %d\n", (payload[1] >> 0) & 1);
				
				if((payload[1] >> 4) & 1)
				{
					fprintf(stderr, "                                 PCR: -\n");
				}
				
				if((payload[1] >> 3) & 1)
				{
					fprintf(stderr, "                                OPCR: -\n");
				}
				
				if((payload[1] >> 2) & 1)
				{
					fprintf(stderr, "                    Splice countdown: -\n");
				}
				
				if((payload[1] >> 1) & 1)
				{
					fprintf(stderr, "       Transport private data length: -\n");
				}
				
				fprintf(stderr, "---------------------------------------\n");
			}
			
			/* Move payload pointer ahead to actual payload */
			payload_len -= payload[0] + 1;
			payload += payload[0] + 1;
		}
		
		if((pkt[1] >> 6) & 1)
		{
			if(pes_len > 0)
			{
				_parse_pes(pes, pes_len);
			}
			
			pes_len = 0;
		}
		
		if(pes_len >= 0)
		{
			if(pes_len + payload_len >= 1024 * 4)
			{
				fprintf(stderr, "PES packet too large\n");
				return(-1);
			}
			
			memcpy(&pes[pes_len], payload, payload_len);
			pes_len += payload_len;
		}
		
		counter = (pkt[3] + ((pkt[3] >> 4) & 1)) & 0x0F;
		
		if(verbose)
		{
			fprintf(stderr, "\n");
		}
		
		if(pad > 0)
		{
			fseek(fin, pad, SEEK_CUR);
		}
	}
	
	fclose(fout);
	fclose(fin);
	
	fprintf(stderr, "Dumped %d lines\n", olines);
	
	return(0);
}

