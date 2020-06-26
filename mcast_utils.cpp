/*
 *  本文件将多播所用到的操作进行封装
 *  基于 IPV4 实现多播 不考虑 协议无关性
 */

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include<stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>
#include<stdlib.h>
#include<string.h>
#include<netdb.h>
#include<unistd.h>
namespace mcast_utils{

typedef sockaddr_in SAI;
typedef sockaddr SA;
typedef in_addr AI;
typedef in_port_t PORT_T;
const size_t ADDR_LENGTH = INET_ADDRSTRLEN+1;


int socket_udp(int protocol =0){
	// 返回 sockfd
	return socket(AF_INET,SOCK_DGRAM,protocol);
}

int  set_sockaddr_in( sockaddr_in& saddr, const char* ip, const PORT_T p){
	/*
	 * return value 1 正确 0 格式不对 -1 地址族错误
	 */
	saddr.sin_family = AF_INET;
	saddr.sin_port =htons(p);    // 需要转换字节序
	return inet_pton(AF_INET,ip,&(saddr.sin_addr.s_addr)) ;
}

// 这里接口设计的有点问题
void parse_sockaddr_in( const sockaddr_in& saddr, char* dst, PORT_T& port){
	inet_ntop(AF_INET,&(saddr.sin_addr), dst, INET_ADDRSTRLEN);	
	port = ntohs(saddr.sin_port);  // 需要转换字节序
}
int get_localif_info(int sockfd,string& ip, PORT_T& port){
	// 获取和sockfd绑定的本机ip和端口
	SAI s_addri;
	socklen_t length = sizeof(s_addri);
	int result = getsockname(sockfd,(SA*)(&s_addri),&length);
	// 将 ip转化为 STRING
	char* buf = new char[INET_ADDRSTRLEN];
	parse_sockaddr_in(s_addri,buf,port);
	ip = buf;
	return result ; 
	
}

int get_local_ip(string& lip){

// 通过 gethost name 和 gethost by name 获取本机ip, 并选择第一个

    char hname[128];
    struct hostent *hent;
    int i;

    gethostname(hname, sizeof(hname));

    hent = gethostbyname(hname);
    char* buf = new char[INET_ADDRSTRLEN];
    for(i = 0; hent->h_addr_list[i]; i++) {
	inet_ntop(AF_INET,(struct in_addr*)(hent->h_addr_list[i]),buf,INET_ADDRSTRLEN);
	lip = buf;
	if(lip == "127.0.0.1" || "0.0.0.0") continue;
	return 0;

    }
return -1;   // -表示都没有找到

}
int mcast_join(int sockfd, const SAI& sock_addr , const char* if_ip=NULL , const int if_index=0){
	/*
	 *  sockfd 套接子描述符
	 *  sock_addr sock的地址结构
	 *  if_ip 将要加入的多播的接口IP
	 *  if_index 接口的index
	 *
	 *  return value  : 0 成功 -1 失败 和 setsockopt 的返回值相同
	 */
	struct in_addr  if_addr;
	struct ip_mreqn req;
	
	// 设置多播ip
	req.imr_multiaddr = sock_addr.sin_addr;

	// 设置接口ip
	
	if(if_ip == NULL &&  if_index ==0){
		if_addr.s_addr = INADDR_ANY;
	}else{
		if (inet_pton(AF_INET,if_ip,&(if_addr.s_addr)) !=1){
			return -1;
		}
	}
	// 设置结构体
	req.imr_address = if_addr;
	req.imr_ifindex = if_index;
	return setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP,&req,sizeof(req));
}

int mcast_leave( int sockfd, const SAI& sock_addr, const char* if_ip = NULL, const int if_index =0){
	/*
	 * 参数 和 mcast_join 的含义基本相同
	 */
	struct in_addr  if_addr;
	struct ip_mreqn req;
	
	// 设置多播ip
	req.imr_multiaddr = sock_addr.sin_addr;

	// 设置接口ip
	
	if(if_ip == NULL &&  if_index ==0){
		if_addr.s_addr = INADDR_ANY;
	}else{
		if (inet_pton(AF_INET,if_ip,&(if_addr.s_addr)) !=1){
			return -1;
		}
	}
	// 设置结构体
	req.imr_address = if_addr;
	req.imr_ifindex = if_index;
	return setsockopt(sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP,&req,sizeof(req));

}

int mcast_leave(int sockfd, const ip_mreqn& req){

	return setsockopt(sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &req,sizeof(req));
}

int set_mcast_loop(int sockfd, bool isloop){
	int value = (int)isloop;
	return setsockopt(sockfd ,IPPROTO_IP, IP_MULTICAST_LOOP ,&value, sizeof(int));
}

int set_mcast_ttl(int sockfd,unsigned short TTL){
	return setsockopt(sockfd,IPPROTO_IP, IP_MULTICAST_TTL,&TTL,sizeof(TTL));
}

int set_msock_timeout(int sockfd,int seconds=0,int micro_seconds =0){
	struct timeval tv;
	tv.tv_sec = seconds;
	tv.tv_usec = micro_seconds;
	return setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
}
ssize_t Recvfrom( int sockfd, void* buf , size_t nbytes, SAI* from , socklen_t *addrlen, int flags=0)
{
	/*
	 *这个函数的目的是对原始的函数进行封装，日后如果要改动的话，改这个函数即可，增强可扩展性
	 *目前只是简单套一层皮, 接口有所不同，直接使用 intnet的套接子接口
	 */
	// 返回实际收到的字节数
	return   recvfrom(sockfd, buf, nbytes,flags,(sockaddr*)from,addrlen);

}
ssize_t Sendto( int sockfd, const void* buf , size_t nbytes, const SAI* to , const socklen_t addrlen, int flags=0)
{
	return sendto(sockfd,buf,nbytes,flags,(sockaddr*)to,addrlen);

}



























}
