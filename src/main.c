#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<pcap.h>
#include<errno.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<linux/wireless.h>
#include<netinet/if_ether.h>

#include <sqlite3.h> 

typedef struct mac_header
{
    unsigned char fc[2];
    unsigned char id[2];
    unsigned char add1[6];
    unsigned char add2[6];
    unsigned char add3[6];
    unsigned char sc[2];
}mac_header;

typedef struct frame_control
{
    unsigned protocol:2;
    unsigned type:2;
    unsigned subtype:4;
    unsigned to_ds:1;
    unsigned from_ds:1;
    unsigned more_frag:1;
    unsigned retry:1;
    unsigned pwr_mgt:1;
    unsigned more_data:1;
    unsigned wep:1;
    unsigned order:1;
}frame_control;

typedef struct beacon_header
{
    unsigned char timestamp[8];
    unsigned char beacon_interval[2];
    unsigned char cap_info[2];
}beacon_header;

char *ether_ntoa_rz(const struct ether_addr *addr, char *buf)
{
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr->ether_addr_octet[0], addr->ether_addr_octet[1],
            addr->ether_addr_octet[2], addr->ether_addr_octet[3],
            addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
    return buf;
}

char *ether_ntoa_z(const struct ether_addr *addr)
{
    static char buf[18];    /* 12 digits + 5 colons + null terminator */
    return ether_ntoa_rz(addr, buf);
}

void test2()
{
	union aword
	{
			unsigned int a;
			char b[4];
	} c;


	c.a=1;
	if(0==c.b[0])
	{
		printf("big endian\n");
	}else
	{
		printf("little endian\n");
	}
}

void print_my( const u_char * start,int len)
{
	int i = 0;
	printf("------------------------------------\n");
	for( i=0; i< len ;i++ )
	{
		if(i%16 == 0)
			printf("\n");
		printf("%02X ",(unsigned char)*(start+i));
	
	}
	printf("------------------------------------\n");
}

void packet_decoder(u_char * useless, const struct pcap_pkthdr *pkthdr,
const u_char * packet)
{
    //printf("Got Packet\n");
    char ssid[32], *temp;
	
	//there is a radiotap header of 18 bits
	struct mac_header *p = (struct mac_header *) (packet+18);
	//struct mac_header *p = (struct mac_header *) packet+18;
    
    struct frame_control *control = (struct frame_control *)p->fc;
    //temp = (char *)(packet + sizeof(struct mac_header)+sizeof(struct beacon_header));
	
	temp = (char *)(packet +18 + sizeof(struct mac_header)+sizeof(struct beacon_header));

    memset (ssid, '\0', 32);
	//print_my(packet,pkthdr->len);
	
	
	
    // check if frame is beacon frame
	/*
	printf("protocole:%x \ttype:%x\tsubtype:%x",control->protocol,control->type,control->subtype);
	printf("%x %x %x %x %x %x %x %x %x %x %x ",control->protocol,control->type,control->subtype
		,control->to_ds,control->from_ds,control->more_frag,
		control->retry,control->pwr_mgt,control->more_data,
		control->wep,control->order);
	printf("\txxx%o, %x, %u",control,control,control);
	printf("\txxx%x, %x, %x\n",p->fc,control->type,control->subtype);
	*/
    if ((control->protocol==0)&&(control->type==0)&&(control->subtype==4))
    {
		//temp[1] contains the size of the ssid field and temp[2] the beginning ofthe ssid string .
		//memcpy (ssid, &temp[2], temp[1]);
		printf ("\n\nFound SSID : \n");
		printf ("Destination Add : %s\n", ether_ntoa_z (p->add1));
		printf ("Source Add : %s\n", ether_ntoa_z (p->add2));
		printf ("BSSID : %s\n", ether_ntoa_z (p->add3));
		//printf ("ssid = %s\n", ssid);
    }
}

static int callback(void *NotUsed, int argc, char **argv, char **azColName){
   int i;
   for(i=0; i<argc; i++){
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}


static int callback_getnumber(void *NotUsed, int argc, char **argv, char **azColName){
   int *count = (int *)NotUsed ;
   *count = argc;
   return 0;
}

void packet_decoder_db(u_char * useless, const struct pcap_pkthdr *pkthdr,
const u_char * packet)
{
    
    char ssid[32], *temp;
	sqlite3 *db = (sqlite3 *) useless;
	char *zErrMsg = 0;
	int  rc;
	char sql[100]={0};
	int count=0;
	
	//there is a radiotap header of 18 bits
	struct mac_header *p = (struct mac_header *) (packet+18);
	//struct mac_header *p = (struct mac_header *) packet+18;
    
    struct frame_control *control = (struct frame_control *)p->fc;
    //temp = (char *)(packet + sizeof(struct mac_header)+sizeof(struct beacon_header));
	
	temp = (char *)(packet +18 + sizeof(struct mac_header)+sizeof(struct beacon_header));

    memset (ssid, '\0', 32);

    if ((control->protocol==0)&&(control->type==0)&&(control->subtype==4))
    {

		printf ("\n\nFound SSID : \n");
		printf ("Destination Add : %s\n", ether_ntoa_z (p->add1));
		printf ("Source Add : %s\n", ether_ntoa_z (p->add2));
		printf ("BSSID : %s\n", ether_ntoa_z (p->add3));
		
		//squery
		sprintf(sql," select * from  mac_log where mac='%s' and date > datetime('now','-5 minute') ;",ether_ntoa_z (p->add2));
		rc = sqlite3_exec(db, (char *)sql, callback_getnumber, (void *)&count, &zErrMsg);
		if( rc != SQLITE_OK ){
			printf("SQL error: %s\n", zErrMsg);
			sqlite3_free(zErrMsg);
		}else{
		  //printf("insert db success\n");
		}
		
		if(count <= 0 )
		{
			//write database		
			sprintf(sql," insert into mac_log values(NULL ,'%s' ,datetime('now')) ;",ether_ntoa_z (p->add2));
			//printf("%s",sql);
			rc = sqlite3_exec(db, (char *)sql, callback, 0, &zErrMsg);
			if( rc != SQLITE_OK ){
			printf("SQL error: %s\n", zErrMsg);
			  sqlite3_free(zErrMsg);
			}else{
			  //printf("insert db success\n");
			}
		}
    }
}



int main(int argc, char **argv)
{
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
	char *file = NULL;
	sqlite3 *db;
	char *zErrMsg = 0;
	int  rc;
	char *sql;
	
    if(argc<=2)
    {
        printf ("usage : %s capture_device sql_file_path\n", argv[0]);
        exit (1);
    }
	file =  argv[2];
	
	
	//pcap initialisation
    handle = pcap_open_live (dev, BUFSIZ, 0, -1, errbuf);

    if (handle == NULL)
    {
        printf ("pcap_open_live : %s\n", errbuf);
        exit (1);
    }
	
	
	
	/* Open database */
	rc = sqlite3_open(file, &db);
	if( rc ){
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		exit(0);
	}else{
		fprintf(stdout, "Opened database successfully\n");
	}
	//create database table 
	sql = "CREATE TABLE IF NOT EXISTS mac_log (" \
		"id INTEGER  PRIMARY KEY  AUTOINCREMENT NOT NULL," \
		"mac CHAR(17)  NOT NULL ," \
		"date datetime NOT NULL " \
		");";
	
	rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
	if( rc != SQLITE_OK ){
	fprintf(stderr, "SQL error: %s\n", zErrMsg);
	  sqlite3_free(zErrMsg);
	}else{
	  fprintf(stdout, "Table created successfully\n");
	}
	
	
	
    printf ("\nStarting Capture ...........\n");
	// tell pcap to pass on captures frames to our packet_decoder fn
    //pcap_loop(handle, -1, packet_decoder, null);
	pcap_loop(handle, -1, packet_decoder_db, (u_char *)db);
	
	sqlite3_close(db);
    return (0);
}
