/*
 * 真正的多播应用类
 *
 *
 */

#include<vector>
#include<unordered_map>
#include"file_utils.cpp"
#include"mcast_class.cpp"
#include"security_utils.cpp"
#include<iostream>
#include<string.h>
#include<pthread.h>
#include<unistd.h>
using namespace std;
using namespace file_utiles;
using namespace mcast_class;
using namespace security_utils;
// 一些和应用层相关的协议常量

// 应用层协议的初步设计    
// 应用层协议初步设计， 头部固定是 4byte 包类型 + 60 byte 的可选空间，一共 64 byte
typedef int MSG_TYPE;
static const MSG_TYPE MSG_MAX = 4;
static const MSG_TYPE MSG_MIN =1;
static const MSG_TYPE MSG_SEND = 1;    // 发送消息

static const MSG_TYPE FILE_SEND =2 ;  // 传输文件
static const MSG_TYPE UPDATE = 3 ;   // 更新密钥
static const MSG_TYPE FIND = 4  ;    // 发送报文，寻找目前在同一个多播组里的所有成


class McastApp{
	typedef string  S_KEY; // 对称加密的密钥
	typedef string  AS_KEY;  // 非对称加密的密钥
	typedef pair<S_KEY,AS_KEY> KEY;
	typedef pair<string,KEY> membership;  
	typedef unordered_map<string,KEY> MULTI_GROUP;  // 多播组成员 
// 主类

public:
	McastApp(const string& lip,const string& group_ip, const unsigned short send_port, const unsigned short recv_port,const unsigned short TTL, const size_t buf );
	~McastApp(); 	
	int send_message(const string& message);  // 发送文字消息
	int send_file(const string& file_path);  // 发送文件
	void recv();      // 接收函数
	void send(char cmd, const string& arg);
	int recv_message( string& msg, const string& from_ip);
	int recv_file(string& file_path,const string& from_ip);
	void find_members();                   // 多播发送自己对称加密和非对称加密的密钥
	void delete_members( const string& ip);   // 将指定IP的用户从自己的用户列表中删除
	void update_des(const string& des,const string& key);     // 对多波所有成员更新对称加密密钥
	void recv_find_msg(const string& from);   // 收到了别人的find消息
	void recv_update_msg(const string & from); // 收到了 update消息
	void list_members();      // 以列表形式展示所有成员
	void print_help();
private:
	// 类成员
	
	// 文件相关
	string message;         //保存消息的缓冲
	string default_save_path ="./recv_file" ;  // 默认保存的根目录
	size_t buffer_size;          // buffer的大小,发送和接收用相同的buffer
	char* send_buffer= NULL;           // 发送 buffer
	char* recv_buffer= NULL; 	  	// 接收 buffer	
	size_t head_size = 32;      //头部固定 字节数
	int file_name_size = 32;
	// socket
	string ip ;                  // 本机ip
	mcast_socket send_socket;
	mcast_socket  recv_socket;
	// 多播组相关
	MULTI_GROUP group_members;    // 多播祖
	AS_KEY rsa_pub_key;       // rsa 公钥
	AS_KEY rsa_pri_key;       // rsa 私钥
	S_KEY des_key;            // des 密钥

	size_t pub_key_length = 8;
	size_t pri_key_length = 2048;
};



//类函数定义
McastApp::McastApp(const string& lip,const string& group_ip, const unsigned short send_port, const unsigned short recv_port, const unsigned short TTL=1, const size_t buf = 4096)
	:ip(lip),send_socket(group_ip.c_str(),send_port),recv_socket(group_ip.c_str(),recv_port),buffer_size(buf){
		// 构造函数生命 发送套接字和接收 socket	
		// 初始化buffer
		send_buffer = new char[buffer_size];
		recv_buffer = new char[buffer_size];		
/*
		// 利用 gethostname 获取本机ip
		if(get_local_ip(ip) ==-1) {
			cout<<"无法获取本机ip"<<endl;
			return ;
		}
		*/
		// bind操作
		send_socket.mbind(ip);
		recv_socket.mbind();   //接收方的端口必须和多播组端口相同
		// join操作    接收方才需要join
		recv_socket.mjoin();

				// 生成初始化密钥
		pub_key_length = 8;
		pri_key_length = 2048;;
		des_key = generate_des_key(pub_key_length,pub_key_length);
		generateRSAKey(rsa_pub_key,rsa_pri_key,pri_key_length);
	
		// 设置 sock的TTL 和 超时时间
		send_socket.set_mtt(TTL);
		recv_socket.setTimeOut(3,0);   //设置超时3秒
		
		// 发送 find包
		
	
}	

McastApp::~McastApp(){
	// 释放资源
	if(send_buffer!=NULL) delete[] send_buffer;
	if(recv_buffer!=NULL) delete[] recv_buffer;	
	recv_socket.mleave();
	send_socket.mclose();
	recv_socket.mclose();
}

void McastApp::list_members(){
	
	int index = 1;
	for(auto & m : group_members){
		cout<<index<<" "<<m.first<<endl;
		index ++;
	}

}
void McastApp::send(char cmd, const string& arg){
	/*
	 *发送函数, 控制四种类型的发送
	 */
	switch(cmd){
		case 'M' : 
			// 发送消息
			send_message(arg);
			break;
		case 'F' : 
			// 发送文件
			send_file(arg);
			break;
		case 'G' :
			// 向组成员广播自己的信息
			find_members();
			break;
		case 'D':
			//删除某个组成员
			delete_members(arg);
		break;
		default :
			cout<<"无效命令，输入 ? 查看帮助"<<endl;
	}

}
int  McastApp::send_message(const string& message){
	// 发送消息
	memset(send_buffer,0,head_size);
	//头文件
	// 先写入消息类型
	char* offset = send_buffer;
	memcpy(offset,(void*)(&MSG_SEND),sizeof(MSG_SEND)); // 4个字节
	offset+= sizeof(MSG_SEND);

	// 数据长度
	unsigned short length = message.size();
	memcpy(offset,&length,2);  // 加入消息长度，不包含最后一个'\0'字符，即数据到小
	offset+=2;
	
	
	// 发送头文件
	send_socket.msendto(send_buffer,head_size);
	memset(send_buffer,0,head_size);

	//数据文件
	string  key = des_key;    //这里key 之后加入组管理的时候再说
	//加密,并把加密后的数据拷入缓冲区
	
	size_t result_length = 0;
	des(message.c_str(),message.length(),send_buffer,key,	0,result_length); //加密,result_length 是加密后的长度
	
	int result =  send_socket.msendto(send_buffer, result_length);
	// 清空发送缓冲区
	memset(send_buffer,0,buffer_size);
}

int McastApp::send_file(const string& filepath){
	/*
	 * return value >0 正确， =-1 出错， -2 打开的不是普通文件
	 */
	// 发送文件
	size_t size;   //要发送的文件的大小
	int file_fd = file_utiles::OpenRFile(filepath,&size);
	if(file_fd<0) 
	{
		cout<<"文件路径错误！"<<endl;
		return file_fd;   // 如果打开文件出错,返回错误码
	}
	// 头文件
	// 写入消息类型
	memset(send_buffer,0,head_size);
	char* offset = send_buffer;
	memcpy(offset,(void*)(&FILE_SEND),sizeof(FILE_SEND)); // 4个字节offset+= sizeof(MSG_SEND);
	offset+= sizeof(FILE_SEND);
		
	// 文件大小 4个字节
	memcpy(offset,&size,sizeof(size_t));
	offset += sizeof(size_t);
	// 发送头文件
	
	send_socket.msendto(send_buffer,head_size);

	// 数据部分,
	
	string key = des_key;
	// 文件名大小固定分配file_name_size个字节
	
	size_t file_name_offset = get_file_name(filepath.c_str());
	unsigned short file_name_length = filepath.size()-file_name_offset;

	size_t result_length =0;
	// 加密，并将拷贝到发送缓冲区
	des(filepath.c_str()+file_name_offset,min(file_name_length+1,file_name_size),send_buffer,key,0,result_length);
	// +1 表示把原来的 '\0'也算上去了

	// 发送file_name_size个字节的文件名，为了编程序方便
	send_socket.msendto(send_buffer,file_name_size);  // 固定32个字节
	memset(send_buffer,0,file_name_size);
	
	// 开始发送文件本体,直接整个block发送
	size_t left = size;   // 剩下的发送量
	char* en_buffer = new char[buffer_size];
	while(left>=buffer_size){
		//读数据，读整个block
		ReadBlock(file_fd,en_buffer,buffer_size);

		// 加密
		
		des(en_buffer,buffer_size,send_buffer,key,0,result_length); //加密一整个buffer
		send_socket.msendto(send_buffer,buffer_size);
		left-=buffer_size;
		//延迟发送防止丢包
		
		usleep(500);   //延迟 0.5 ms 发送包 防止接收方溢出
	}
	memset(send_buffer,0,buffer_size);
	memset(en_buffer,0,buffer_size);
	// 发送最后一个block并加密
	
	while(left>0){
		// 因为要向上去整
		if(left<= buffer_size - 8){
			ReadBlock(file_fd,en_buffer,left);  // 取最后的数据
			// 加密
			des(en_buffer,left,send_buffer,key,0,result_length);
			send_socket.msendto(send_buffer,result_length);
			break;
		}else{
			// 否则因为buffer不够，需要分两次发送
			result_length= floor(float(left)/8)*8;
			ReadBlock(file_fd,en_buffer,result_length);
			// 加密
			des(en_buffer,result_length,send_buffer,key,0, result_length);
			send_socket.msendto(send_buffer,result_length);
			left-=result_length;  //还要发送一次			
		}
		memset(send_buffer,0,buffer_size);
		memset(en_buffer,0,buffer_size);
	}
	//释放资源
	close(file_fd);
	delete []en_buffer;
	cout<<"send done"<<endl;
	return size;
}

void McastApp::recv(){
	// 接收函数， 首先一直 block接收消息类型
	
	int packet_type =-1;
	mcast_socket::SESS_T from;   // 接收方
	while(true){
		// 先收头文件，并解析消息类型
		ssize_t recved = recv_socket.mrecvfrom(recv_buffer,head_size,from)	;
		memcpy(&packet_type,recv_buffer,sizeof(MSG_TYPE));
		// 判断收到的是不是真消息
		if(packet_type>= MSG_MIN && packet_type<=MSG_MAX){

			// 收到的是真消息
			switch(packet_type){
				case MSG_SEND: 
					       recv_message(message,from.first);
					       cout<<from.first<<": "<<message<<endl;
					       break;
				case FILE_SEND: recv_file(default_save_path,from.first);
						break;
				case FIND:
						recv_find_msg(from.first);
						break;
				case UPDATE:
						recv_update_msg(from.first);
						break;
				default:
				;

			}
			cout<<"done!"<<endl;
		}
	}
}
int McastApp::recv_message(string& msg,const string& from_ip){
	// 接收消息，解密并把消息放到缓冲区里
        // 正确表示

	// 解析剩下的头文件
	mcast_socket::SESS_T from;
	cout<<"收到来自"<<from_ip<<"的消息"<<endl;
	char* offset = recv_buffer;
	offset+=4;

	unsigned short length =0; // 消息长度
	memcpy(&length,offset,2);  
	offset+=2;
	
	memset(recv_buffer,0,head_size);
	// 数据部分
	
	string key =group_members[from_ip].first;
	// 接收数据
	
	recv_socket.mrecvfrom(recv_buffer,buffer_size,from);  

	// 得到数据长度了,计算加密后的长度
	size_t result_length = ceil(float(length)/8) * 8;

	// 取出message
	char* cmsg = new char[result_length]; 
	// 解密
	des(recv_buffer,result_length,cmsg,key,1,result_length);
	
	// 将解密后转化为 string
	
	cmsg[length] ='\0'; // 最后一个字符设置为终结符

	// delete
	
	//delete [] cmsg;
	memset(recv_buffer,0,buffer_size);
	msg.assign(cmsg,length+1);
	delete [] cmsg;
	return length ;

}

int McastApp::recv_file( string& dir_path, const string& from_ip){
	// 接收文件，保存在目录 dir_path下
	cout<<"收到来自: "<<from_ip<<"的文件"<<endl;
	cout<<"开始接收文件"<<endl;

	mcast_socket::SESS_T from;
	
	// 解析剩余的头文件

	char* offset = recv_buffer;
	offset += sizeof(MSG_TYPE);
/*
	char* filename = new char[file_name_length+1];                //文件名
	memcpy(filename,offset,file_name_length+1);
	offset+= (file_name_length+1);
	string filepath = dir_path + filename;
*/

	// 读文件大小
	size_t file_size =0;
	memcpy(&file_size,offset,sizeof(size_t));
	offset+= sizeof(size_t);

	cout<<"文件大小"<<file_size<<endl;
	memset(recv_buffer,0,head_size);

	// 数据部分
	string key = group_members[from_ip].first;

	// 读文件名，为了编程方便 两次 recvfrom
	char* filename = new char[file_name_size+1];  //固定大小,file_name_size+1,最后一个用来存放 '\0'
	filename[file_name_size] ='\0';  //最后一位一定是'0',防止过长
	recv_socket.mrecvfrom(recv_buffer,file_name_size,from);   

	//解密
	size_t result_length =0;
	des(recv_buffer,file_name_size,filename,key,1,result_length); // 因为已经把'\0'一起编码进去了
	string filepath = dir_path+'/'+filename;

	// 创建新文件
	int new_file_fd = CreateRFile(filepath);
	if(new_file_fd<0) return -1;

	memset(recv_buffer,0,file_name_size);
	cout<<"文件名为"<<filepath<<endl;

	// 开始接收真正的数据,一个block一个block收
	size_t left= file_size;

	size_t blocks = ceil(float(left)/buffer_size);
	char* en_buffer = new char[buffer_size];
	//接收整个block
	while(left>=buffer_size){
		size_t recv_this_time = recv_socket.mrecvfrom(recv_buffer,buffer_size,from);
		// 解密
		des(recv_buffer, recv_this_time,en_buffer,key,1,result_length);
	        WriteBlock(new_file_fd,en_buffer,recv_this_time);
		memset(recv_buffer,0,buffer_size);	
		memset(en_buffer,0,buffer_size);
		left -= recv_this_time;
	}
	// 最后一个 block
	while(left>0){
		size_t recv_this_time = 0;
		// 因为要向上去整
		if(left<= buffer_size - 8){
			// 要先计算加密后的大小
			recv_this_time = ceil(float(left)/8)*8;
			recv_socket.mrecvfrom(recv_buffer,recv_this_time,from); // 读最后的数据
			// 解密
			des(recv_buffer,recv_this_time,en_buffer,key,1,result_length);


			// 写入文件
			WriteBlock(new_file_fd,en_buffer,left);  //注意只写left进取
			break;
		}else{
			cout<<"情况2"<<endl;
			// 否则因为buffer不够，需要分两次发送
			recv_this_time= floor(float(left)/8)*8;
			recv_socket.mrecvfrom(recv_buffer,recv_this_time,from); // 读最后的数据
			// 解密
			des(recv_buffer,recv_this_time,en_buffer,key,1,result_length);


			// 写入文件
			WriteBlock(new_file_fd,en_buffer,recv_this_time);  //注意只写recv_this_time进取
		
			left-=recv_this_time;  //还要读一次			
		}
		memset(recv_buffer,0,buffer_size);
		memset(en_buffer,0,buffer_size);
	}
	//释放资源
	delete []en_buffer;
	close(new_file_fd);
	cout<<"文件接收结束"<<endl;
	return file_size;   //返回接收到的文件大小
}
void McastApp::find_members()                   
{
      // 多播发送自己的公钥和私钥
      
	// header
	memset(send_buffer,0,head_size);
	//头文件
	// 先写入消息类型
	char* offset = send_buffer;
	memcpy(offset,(void*)(&FIND),sizeof(MSG_TYPE)); // 4个字节
	offset+= sizeof(MSG_TYPE);

	// 发送头文件
	send_socket.msendto(send_buffer,head_size);
	memset(send_buffer,0,head_size);
	// data
	
	offset = send_buffer;	
	// 添加 8 位的 对称密钥, 这里还是没设计好，没有摆脱无关性
	memcpy(offset, des_key.c_str(), pub_key_length);
	offset+= pub_key_length;
	// 添加 2048 位的 rsa 公钥， 这里我默认 发送缓冲区 为 4k 偷个懒
	memcpy(offset, rsa_pub_key.c_str(), pri_key_length);
	// 发送密钥数据
	send_socket.msendto(send_buffer,pub_key_length+pri_key_length);



}
void McastApp::delete_members( const string& dest_ip)  {
	// 多播组管理，将组成员删除
	
	auto iter = group_members.find(dest_ip);
	if( group_members.end() == iter){
		cout<<"没有该组成员"<<endl;
		return ;
	}
	// 删除组成员
	cout<<"开始更新密钥"<<endl;
	group_members.erase(iter); 

	// 对所有的剩余组成员 循环发送更新消息
//	更新密钥
	des_key = generate_des_key(pub_key_length,pub_key_length);

	for(auto iter = group_members.begin(); iter!= group_members.end();iter++){
		// 发送更新密钥,循环
		update_des( iter->first,des_key);
	}
}
	
void McastApp::update_des(const string& dest_ip,const string& key){
	// 用非对称加密的方式给 des_ip 更新密钥
	if(group_members.find(dest_ip) == group_members.end()) return ; // 找不到这个ip
	char* offset = send_buffer;
	// 构造头部
	memcpy(offset,(void*)(&UPDATE),sizeof(MSG_TYPE));  // 消息类型
	offset += sizeof(MSG_TYPE);
	// 在头部加入目的 ip 32 位 4 个字节
	
	inet_pton(AF_INET,dest_ip.c_str(),offset);	
	
	// 发送头文件
	send_socket.msendto(send_buffer,head_size);
	memset(send_buffer,0,head_size);

	// data部分
	
	// 对des密钥 进行加密
	
	
	// 对密钥公钥加密

	string en_des_key = rsa_pub_encrypt(des_key, group_members[dest_ip].second);
	// 发送加密后的密钥
	
	memcpy(send_buffer,en_des_key.c_str(),pub_key_length);  // 不包含 '\0'

	// 发送数据
	send_socket.msendto(send_buffer,pub_key_length);
}


void McastApp::recv_find_msg(const string & src_ip){
	// 收到 find消息，find消息也可以看成对所有组成员更新密钥
	// 解析剩下的头文件
	mcast_socket::SESS_T from;
	cout<<"收到来自"<<src_ip<<"find 消息"<<endl;
	// 解析数据部分密钥
	memset(recv_buffer,0,head_size);
	char* pub_key = new char[pub_key_length+1];
	pub_key[pub_key_length] = '\0';

	char* pri_key = new char[pri_key_length+1];
	pri_key[pri_key_length] = '\0';
	
	recv_socket.mrecvfrom(recv_buffer,pub_key_length+pri_key_length,from); //接收key
	// 公钥
	memcpy(pub_key,recv_buffer,pub_key_length);

	// 私钥， 这里笔误，应该是分别对应 des密钥和ras密钥
	memcpy(pri_key, recv_buffer+pub_key_length, pri_key_length);

	// 保存密钥
	
	group_members[src_ip].first =pub_key;

	group_members[src_ip].second = pri_key;
	cout<<"将该成员加入组"<<endl;
}

void McastApp::recv_update_msg(const string& src_ip){
	// 收到 update消息
	
	// header 剩下部分
	mcast_socket::SESS_T from;
	char* offset = recv_buffer+ sizeof(MSG_TYPE);
	// 比较是不是发给自己的
	in_addr local_ip;
	inet_pton(AF_INET, this->ip.c_str(), &local_ip);
	if( memcmp(&local_ip,offset, sizeof(local_ip)) !=0){
		// 把 socket缓冲区剩下的内容读出来之后不做事了
		recv_socket.mrecvfrom(recv_buffer,pub_key_length,from);
		memset(recv_buffer,0,buffer_size);		
		return ;
	}
	cout<<"收到来自:"<<src_ip<<"的更新key"<<endl;
	memset(recv_buffer,0,head_size);
	// data部分
	
	// 需要取出密钥
	char* de_ckey = new char[pub_key_length+1] ;
	de_ckey[pub_key_length] = '\0';

	recv_socket.mrecvfrom(recv_buffer,pub_key_length,from);  // 接收密钥

	memcpy(de_ckey, recv_buffer,pub_key_length);
	string de_key = de_ckey;
	// 解密,并更新密钥
	group_members[src_ip].second = rsa_pri_decrypt(de_key,rsa_pri_key);

	memset(recv_buffer,0,pub_key_length);
}

void McastApp::print_help(){
	// 打印帮助信息
	cout<<"S "<<"发送消息"<<endl;
	cout<<"F "<<"发送文件"<<endl;
	cout<<"D "<<"删除成员"<<endl;
	cout<<"G "<<"广播本机消息"<<endl;
        cout<<"L "<<"合法成员列表"<<endl;
	cout<<"? "<<"打印帮助信息"<<endl;
	cout<<"Q "<<"退出程序"<<endl;
}
void* recvThread(void* arg){
	// 临时测试函数
	McastApp* app = static_cast<McastApp*>(arg);
	app->recv();
}


void control( const string& lip,const string& group_ip, unsigned short send_port, unsigned short recv_port,unsigned short TTL){
	// 流程控制函数
	// 采用多线程的方式 ， 发送方一个线程，接收方一个线程
	cout<<"欢迎使用 Mcast , 输入 ? 打印帮助信息"<<endl;
	McastApp app(lip,group_ip,send_port,recv_port,TTL);

	// 创建子线程
	pthread_t pthid;
	if(pthread_create(&pthid,NULL,recvThread,(void*)(&app))!=0)
		cout<<"线程创建失败"<<endl;
	
	pthread_detach(pthid);
/*
	sleep(4);
//	app.send_message("hello");
	app.send_file("./main.cpp");
	cout<<"发送完成"<<endl;
*/
	bool is_continue = true;
	//主线程
	while(is_continue){
		char cmd;
		string arg;
		cin>> cmd;
		switch(cmd){
			case '?' :
				app.print_help(); break;
			case 'L' :
				cout<<"成员如下"<<endl;
				app.list_members();break;
			case 'G' :
				cout<<"开始组播本机信息"<<endl;
				app.find_members(); 
				break;
			case 'D' :
				cout<<"请输入待删除成员的ip"<<endl;
//				cin>>arg;
				getline(cin,arg); cin.get();
				app.delete_members(arg);
				break;
			case 'F' :
				cout<<"请输入待发送文件的路径"<<endl;
				getline(cin,arg); cin.get();
				app.send_file(arg);
				break;
			case 'S' :
				cout<<"请输入待发送的消息"<<endl;
				getline(cin,arg); cin.get();
				app.send_message(arg);
				break;
			case 'Q' :
				is_continue = false;
				break;
			default:
				cout<<"无效命令，清重新输入"<<endl;


		}

	}

}




