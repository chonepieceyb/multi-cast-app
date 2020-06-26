/*
 *mcast_class.cpp 在 mulcast_utils.cpp 的基础上进一步封装类
 *
 */

#include "mcast_utils.cpp"
#include<string>
#include<vector>
#include<unordered_map>
#include<iostream>
using namespace std;

namespace mcast_class{

using namespace mcast_utils;
class mcast_socket{
	
	// 对多播class做一个封装
	public:	typedef pair<string,PORT_T> SESS_T;   // SESS_T 是 session type的意思，这里是 ip 和端口号的组合
	public:
		mcast_socket(const char* ip, const PORT_T p);
		bool mbind();	
		bool mbind(int flag);
		bool mbind(const string& ip);
		bool mjoin(const char* if_ip, const int if_index);
		bool mleave(const char* if_ip, const int if_index );
		ssize_t  msendto(const void* buf, const size_t bytes);
		ssize_t  mrecvfrom(void* buf, const size_t bytes, SESS_T& from);
		bool set_loop(bool is_loop);
		int set_mtt(unsigned short TTL){
			return set_mcast_ttl(sockfd,TTL);
		}
		int setTimeOut(int seconds, int mseconds){
			return set_msock_timeout(sockfd,seconds,mseconds);
		}
		bool mclose(){
			return close(sockfd);
		}
		// 一些get函数
		
		int get_sockfd(){
			return sockfd;
		}
		string& get_group_ip(){
			return group_ip;
		}
		PORT_T get_port(){
			return port;
		}

	private:
		int sockfd;         // 多播的描述符
		string group_ip;    // 多播的ip
		PORT_T port;  // 多播端口
		SAI saddr;       // socket 地址结构
		
};

mcast_socket::mcast_socket(const char* ip, const PORT_T p):group_ip(ip),port(p){
	// 构造函数，主要将 字符串的ip 和 port转化为 sockaddr
	// 构造 socket
	sockfd = socket_udp();
	if(sockfd ==-1){
		cout<<"mcast_sock inilization error, create socket failed"<<endl;
	}
		if(set_sockaddr_in(saddr,ip,p)!=1){
			cout<<"mcast_sock inilization error, ip error"<<endl;
		}
}

bool mcast_socket::mbind(){
	// 将多播地址进行捆绑，根据 unix网络编程，对多播地址捆绑非必须，这里还没有测试
	// 多播的接收方必须加入多播组，其端口号必须和多播组端口号相同
	if(bind(sockfd,(SA*)(&saddr),sizeof(saddr))==0){
		return true;
	}else{
		return false;
	}

}
bool mcast_socket::mbind(int flag){
	// flag无意义，为了和 mbind()区分，亚元，绑定任意端口号和ip
	SAI saddri ;
	saddri.sin_addr.s_addr = INADDR_ANY;
	saddri.sin_port = 0;
	if(bind(sockfd,(SA*)(&saddri),sizeof(saddri))==0){
		return true;
	}else{
		return false;
	}


}
bool mcast_socket::mbind(const string& sip){
	// 绑定某一个ip
	SAI saddri ;
	set_sockaddr_in(saddri,sip.c_str(),0);
	if(bind(sockfd,(SA*)(&saddri),sizeof(saddri))==0){
		return true;
	}else{
		return false;
	}
}
bool mcast_socket::mjoin(const char* if_ip =NULL, const int if_index =0){
	if(mcast_join(sockfd,saddr,if_ip,if_index) ==0){
		return true;
	}else{
		return false;
	}
}

bool mcast_socket::mleave(const char* if_ip=NULL, const int if_index =0){
	if(mcast_leave(sockfd,saddr,if_ip,if_index) ==0){
		return true;
	}else{
		return false;
	}
}

ssize_t mcast_socket::msendto(const void* buf, const size_t bytes)
{
	return Sendto(sockfd,buf,bytes,&saddr,sizeof(saddr));
}

ssize_t mcast_socket::mrecvfrom(void* buf, const size_t bytes, SESS_T& from){

	// 这里要解析出来
	SAI from_addr;
	socklen_t length= sizeof(from_addr); 
	ssize_t recved =  Recvfrom(sockfd,buf,bytes,&from_addr,&length);

	if(recved<0){
		if(recved ==EWOULDBLOCK || recved == EAGAIN){
			cout<<"发生丢包"<<endl;
		}else{
			return -1;
		}
	}
	char* dst = new char[ADDR_LENGTH];
	parse_sockaddr_in(from_addr,dst,from.second);
	from.first = string(dst);
	return recved;

}
bool mcast_socket::set_loop(bool is_loop=false){	
	if(set_mcast_loop(sockfd,is_loop)==0){
		return true;
	}else{
		return false;
	}
}





























}
