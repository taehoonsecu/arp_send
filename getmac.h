#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ifreq *get_host_mac(char *nic_name){
  // fd - use for communication to get mac address
  int fd;
  struct ifreq *sIfReq;
  sIfReq = (ifreq*)malloc(sizeof(ifreq));
  memset(sIfReq, 0x00, sizeof(ifreq));
  // set the ifreq.ifr_name : the name of nic you use for communication
  strncpy(sIfReq->ifr_name,nic_name,strlen(nic_name));
  fd=socket(AF_UNIX, SOCK_DGRAM, 0);
  if(fd == -1){
    printf("socket() error\n");
    return NULL;
  }

  printf("=== debug == : before ioctl()\n");
  if(ioctl(fd,SIOCGIFHWADDR,sIfReq)<0){
    perror("ioctl() error\n");
    return NULL;
  }
  printf("=== debug == : after ioctl()\n");
  return sIfReq;

}
