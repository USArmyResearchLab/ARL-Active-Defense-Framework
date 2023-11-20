#include <pcap.h>
#include <pthread.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

//interfaces
const char *untrust_iface;
const char *trust_iface;
const char *untrust_tap_iface;
const char *trust_tap_iface;

//bpf filter for redirecting to taps
char filter_file[256];
char *filter;
int filter_size;
struct bpf_program bpf;

//pcap error buffer
char ebuf[256];

//pcap objects
pcap_t	*cap_untrust;
pcap_t	*cap_trust;

//tap fds
int trust_tap=0;
int untrust_tap=0;
//tap stop flag
int stop_taps=0;

long untrust_trust_cnt=0;
long trust_untrust_cnt=0;
long untrust_tap_cnt=0;
long trust_tap_cnt=0;
long untrust_tap_untrust_cnt=0;
long trust_tap_trust_cnt=0;


//threads
pthread_t thread_untrust;	//reads untrust, writes to trust or untrust_tap
pthread_t thread_trust;		//reads trust, writes to untrust or trust_tap
pthread_t thread_untrust_tap;	//reads untrust_tap, writes to untrust
pthread_t thread_trust_tap;	//reads trust_tap, writes to trust

//thread arg struct
struct thread_config {
	char *iface;
	pcap_t *in_pcap;	//capture from this
	pcap_t *out_pcap;	//normally send to this
	int  *tap_fd;		//send to this if the filter matches/read from this
	long *out_w_cnt;	//bytes written to output
	long *tap_w_cnt;	//bytes written to tap
};

//thread configs
struct thread_config config_untrust;
struct thread_config config_trust;
struct thread_config config_untrust_tap;
struct thread_config config_trust_tap;

int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

   if( (fd = open(clonedev, O_RDWR)) < 0 )  return fd;
   memset(&ifr, 0, sizeof(ifr)); //create interface request struct
   ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */
   if (*dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ); //set name from args

   if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
     close(fd);
     return err;
   }

  strcpy(dev, ifr.ifr_name); //copy name back to arg in case we let kernel pick it
  return fd;
}


//reports error and bails
void pcap_error(int err,char *iface){
	fprintf(stderr,"%s: %s %s\n",iface,pcap_statustostr(err),ebuf);
	exit(1);
}

void error(char *msg, char *iface){
	fprintf(stderr,"%s %s: %s\n",msg,iface,strerror(errno));
	exit(1);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
	struct thread_config *t_config=(struct thread_config *)user;
	int nwrite;
	if (t_config->tap_fd && filter_size && pcap_offline_filter(&bpf,h,bytes)) {
		nwrite=write(*t_config->tap_fd,bytes,h->caplen);
		if (nwrite<0) error ("writing",t_config->iface);
		*(t_config->tap_w_cnt)+=nwrite;
	}
	else *(t_config->out_w_cnt)+=pcap_inject(t_config->out_pcap,bytes,h->caplen); //no tap, no filter, or no filter match, write through	
}


void *Capture(void *args){
	struct thread_config *t_config=(struct thread_config *)args;
	fprintf(stderr,"opening %s\n",t_config->iface);
	pcap_loop(t_config->in_pcap, -1, packet_handler, (u_char*) t_config);
	fprintf(stderr,"closing %s\n",t_config->iface);
	struct pcap_stat ps;
	if (!pcap_stats(t_config->in_pcap, &ps)) fprintf(stderr,"%s:\t%s packets: %d captured, %d dropped, %d dropped by interface\n",
							t_config->iface,t_config->iface,ps.ps_recv,ps.ps_drop,ps.ps_ifdrop);
	
	if (t_config->tap_w_cnt) {
		fprintf(stderr,"%s:\t%ld bytes written to interface\n",t_config->iface,*(t_config->out_w_cnt));
		fprintf(stderr,"%s:\t%ld bytes written to tap\n",t_config->iface,*(t_config->tap_w_cnt));
	}
	pthread_exit(NULL);
}


void *TapReader(void *args){
	struct thread_config *t_config=(struct thread_config *)args;
	char buffer[65536]; //read buffer
	fprintf(stderr,"opening %s\n",t_config->iface);
	while (!stop_taps){
		struct timeval tmout; //select timeout
		tmout.tv_sec=1;
		tmout.tv_usec=0;
		//set up an fdset to wait on the tap_fd
		fd_set fdset;
		FD_ZERO(&fdset);
		FD_SET(*t_config->tap_fd, &fdset);
		int rdy = select(*(t_config->tap_fd)+1, &fdset, NULL, NULL, &tmout); //block here until we have a packet ready
		if (rdy < 0) {
			if(errno == EINTR) continue; //ignore interrupted syscall
			else error("select",t_config->iface);
		}
		//printf("%s rdy %d\n",t_config->iface,rdy);
		if (rdy) {  //there is data ready
			int nread=read(*t_config->tap_fd,buffer,sizeof(buffer)); //read from the tap
			if (nread<0) error("reading",t_config->iface);
			*(t_config->out_w_cnt)+=pcap_inject(t_config->out_pcap,buffer,nread); //write to the output interface
		}
	}
	fprintf(stderr,"closing %s\n",t_config->iface);
	pthread_exit(NULL);
}


int read_file(char **buffer, char *filename){
	//read filename into buffer, return size of buffer
	int size = 0; 
	FILE *fp = fopen(filename,"rb");
	if (!fp) error("opening",filename);
	fseek(fp,0,SEEK_END); size=ftell(fp); rewind(fp);
	*buffer = calloc(1,size+1);
	fread(*buffer, size, 1 , fp);
	fprintf(stderr,"%s: %d bytes\n",filename,size);
	fclose(fp);
	return size;
}


void set_filter(){
	//read filter file
	if (filter) free(filter);
	filter_size=read_file(&filter,filter_file);
	//compile the filter
	int e;
	if ((e=pcap_compile(cap_trust,&bpf,filter,1,PCAP_NETMASK_UNKNOWN))) pcap_error(e,filter_file);
}


void setup_pcap(pcap_t **p,const char *iface){
	//sets up a pcap, given a pointer to the pcap_t and the interface
	int e=0;
	if (!(*p=pcap_create(iface,ebuf))) pcap_error(0,(char *)iface);
	if ((e=pcap_set_promisc(*p,1))) pcap_error(e,(char *)iface);
	if ((e=pcap_set_snaplen(*p,65535))) pcap_error(e,(char *)iface);
	if ((e=pcap_set_timeout(*p,1))) pcap_error(e,(char *)iface);
	if ((e=pcap_activate(*p))) pcap_error (e,(char *)iface);
	if ((e=pcap_setdirection(*p,PCAP_D_IN))) pcap_error (e,(char *)iface);
}

int setup_tap(const char *iface){
	//creates and connects a tap interface, returns the fd
	int fd=-1;
	fd=tun_alloc((char*)iface,IFF_TAP|IFF_NO_PI);
	if (fd<0) error("creating",(char *)iface);
	return fd;
}


void start_thread(	pthread_t *t, 
			char* iface, pcap_t *in_pcap, 
			pcap_t *out_pcap, long *out_w_cnt, 
			int *tap_fd, long *tap_w_cnt){

	//create the thread config
	struct thread_config *t_config=calloc(1,sizeof(struct thread_config));
	t_config->iface=iface;
	t_config->in_pcap=in_pcap;
	t_config->out_pcap=out_pcap;
	t_config->tap_fd=tap_fd;
	t_config->out_w_cnt=out_w_cnt;
	t_config->tap_w_cnt=tap_w_cnt;

	//start the thread
	int rc;
	if (in_pcap) rc=pthread_create(t, NULL, Capture, t_config);
	else rc=pthread_create(t, NULL, TapReader, t_config);
	if (rc) error("create thread",iface);
}


void wait_thread(pthread_t *t){
	void *status;
	int rc=pthread_join(*t,&status);
	if (rc) fprintf(stderr,"thread exited (%d)\n",rc);
}

static void handle_sig(int s){
	if (s == SIGHUP) { //reload filter
		struct bpf_program old_bpf=bpf; //save old filter until new one is loaded
		set_filter();	//reload and set filter
		pcap_freecode(&old_bpf); //free old filter
	}
	else { //break capture, threads will exit
		pcap_breakloop(cap_untrust);
		pcap_breakloop(cap_trust);
		stop_taps=1;
	}
}

int main(int argc,const char *argv[]){
	//check args
	if (argc < 5 || argc > 6)  {
		fprintf(stderr,"usage: %s <iface0> <iface1> <tap0> <tap1> <bpf_filter>\n",argv[0]);
		exit(1);
	}

	//set interfaces
	untrust_iface=argv[1];
	trust_iface=argv[2];
	untrust_tap_iface=argv[3];
	trust_tap_iface=argv[4];

	//init pcap objects
	setup_pcap(&cap_untrust,untrust_iface);
	setup_pcap(&cap_trust,trust_iface);
	untrust_tap=setup_tap(untrust_tap_iface);
	trust_tap=setup_tap(trust_tap_iface);

	//load filter
	if (argc == 6) {
		strncpy(filter_file,argv[5],255); 
		set_filter();	
	}

	//set signal handlers
	signal(SIGHUP,handle_sig);
	signal(SIGINT,handle_sig);
	signal(SIGTERM,handle_sig);

	//start the threads
	//capture threads
	start_thread(	&thread_untrust,  //thread
		(char *)untrust_iface,cap_untrust,	//sniff
		cap_trust,	&untrust_trust_cnt,	//write and count
		&untrust_tap,	&untrust_tap_cnt); 	//tap fd and count
	start_thread(	&thread_trust, 
		(char *)trust_iface,cap_trust,
		cap_untrust,	&trust_untrust_cnt,
		&trust_tap,	&trust_tap_cnt);		//t->un/t_tap
	//tapreader threads
	start_thread(	&thread_untrust_tap, 
		(char *)untrust_tap_iface, NULL,
		cap_untrust,	&untrust_tap_untrust_cnt,
		&untrust_tap,	NULL);	//un_tap->un
	start_thread(	&thread_trust_tap, 
		(char *)trust_tap_iface, NULL,
		cap_trust,	&trust_tap_trust_cnt,
		&trust_tap,	NULL);		//t_tap->t

	//wait for threads to exit
	wait_thread(&thread_untrust);
	wait_thread(&thread_trust);
	wait_thread(&thread_untrust_tap);
	wait_thread(&thread_trust_tap);

	pcap_close(cap_untrust);
	pcap_close(cap_trust);
	close(untrust_tap);
	close(trust_tap);

	pthread_exit(NULL);
}

