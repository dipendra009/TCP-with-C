 #include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <iostream>
#include "Minet.h"
#include "tcpstate.h"
#include "tcp.h"
#include "buffer.h"
#include "constate.h"
#include "ip.h"
#include "packet_queue.h"

#define MIN(a,b) (((a)<(b)) ? (a) : (b))
#define INITSEQ 1000
using std::cout;
using std::cerr;
using std::endl;

// Global memory
MinetHandle mux;
MinetHandle sock;
ConnectionList<TCPState> clist;


bool sendBufferHasDataToSend(ConnectionList<TCPState>::iterator& it);


// Timeout Functions
void TimeoutHandler(ConnectionList<TCPState>::iterator &c);
void SetConnectionTimeout( ConnectionList<TCPState>::iterator &it, int inteval=4 ){
			(*it).timeout.SetToCurrentTime();
			(*it).timeout.tv_sec += inteval;
}
bool IsTimeout(Time &current_time, Time &select_timeout);

// MUX Handler
void ListenHandlerFromMux(TCPHeader &tcph, Connection& c);
void SynRcvdHandlerFromMux(TCPHeader& th,Buffer& data,Connection& c);
void SynSentHandlerFromMux(TCPHeader& th,ConnectionList<TCPState>::iterator& cs);
void EstablishedHandlerFromMux(TCPHeader& th,Buffer& data,ConnectionList<TCPState>::iterator& cs);
void CloseWaitHandlerFromMux(TCPHeader& th,ConnectionList<TCPState>::iterator& cs);
void LastAckHandlerFromMux(TCPHeader& th,ConnectionList<TCPState>::iterator& cs);
void ClosingHandlerFromMux(TCPHeader& th,ConnectionList<TCPState>::iterator& cs);
void TimeWaitHandlerFromMux(TCPHeader& th,ConnectionList<TCPState>::iterator& cs);
void FinWait2HandlerFromMux(TCPHeader& th,ConnectionList<TCPState>::iterator& cs);
void FinWait1HandlerFromMux(TCPHeader& th,ConnectionList<TCPState>::iterator& cs);

//Socket Handler
void ConnectHandler(SockRequestResponse& s);
void AcceptHandler(SockRequestResponse& s);
void StatusHandler(SockRequestResponse& s);
void CloseHandler(SockRequestResponse& s);
void WriteHandler(SockRequestResponse& s);

//Tools Functions
void getConnectionFromMux(IPHeader& ipl, TCPHeader& tcph, Connection& c);
void ResetConnection(ConnectionList<TCPState>:: iterator& cs);
void SendSyn(ConnectionList<TCPState>::iterator &ptr);
void SendFin(ConnectionList<TCPState>::iterator &ptr);
void SendSynAck(ConnectionList<TCPState>::iterator &ptr);
void SendAck(ConnectionList<TCPState>::iterator &ptr);
void SendData(ConnectionList<TCPState>::iterator &ptr);
void ReplyWrite(Connection& c,Buffer data, int size, int errno);
void ReplyStatus(Connection& c,int b, int err=EOK){
	SockRequestResponse repl;
	repl.type = STATUS;
	repl.connection = c;
	repl.bytes = b;
	repl.error = err;
	MinetSend(sock,repl);
}
Packet CreatePacket(ConnectionList<TCPState>::iterator &ptr,unsigned char flags);
Packet CreatePayloadPacket(ConnectionList<TCPState>::iterator &ptr, unsigned &bytesize, unsigned int datasize, unsigned char flags);
bool GetAndAnalyzeIPPacket(TCPHeader &tcph, Connection &c, Buffer &data);



int main(int argc, char *argv[])
{
	bool activetmr = false;
	int rc;

	MinetInit(MINET_TCP_MODULE);
	mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
	sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

	if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
		MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
		return -1;
	}

	if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
		MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
		return -1;
	}

	MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

	MinetEvent event;

  	Time current_time, select_timeout;
	while (1) {
	gettimeofday(&current_time, 0);

	activetmr = IsTimeout(current_time, select_timeout);


	if(activetmr == false){
		rc = MinetGetNextEvent(event);
	}
	else if((double)select_timeout==0.0){
		event.eventtype = MinetEvent::Timeout;
	}
	else{
		rc = MinetGetNextEvent(event, (double)select_timeout);
		cout<<"rc"<<rc<<endl;
	}

	if(rc<0){
		cerr << "Error on getting next event." << endl;
		while(1){}
	}
	else if (event.eventtype==MinetEvent::Timeout){
		cout<<"handling timeout...."<<endl;

		ConnectionList<TCPState>::iterator next = clist.FindEarliest();
		while( (next != clist.end()) && ((*next).timeout < current_time) ) {
		  gettimeofday(&current_time, 0);
			TimeoutHandler(next);

		  next = clist.FindEarliest();
		}
    }
    else if (event.eventtype!=MinetEvent::Dataflow || event.direction!=MinetEvent::IN) {
        	MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    }
	else {

		if (event.handle==mux) {
		cout<<"in mux..."<<endl;
        		Connection c;
        		Buffer data;
			TCPHeader tcph;

			GetAndAnalyzeIPPacket(tcph, c, data);

			cout<<"conn"<<conn<<endl;
			ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
			cout<<"cs"<<cs<<endl;
			if(cs != clist.end()) {
			unsigned int connStat = (*cs).state.GetState();
			cout<<"cstate"<<connStat<<endl;
			unsigned char flag = 0;
			tcph.GetFlags(flag);
			if(IS_RST(flag)){
				if((*cs).bTmrActive==false){
					continue;
				}
				else{
					ResetConnection(cs);
					continue;
				}
			}
			unsigned short window;

			tcph.GetWinSize(window);
			(*cs).state.SetSendRwnd(window);
			switch(connStat){
			case CLOSED:
				break;
			case LISTEN:
				ListenHandlerFromMux(tcph, c);
		    		break;
			case SYN_SENT:
				SynSentHandlerFromMux(tcph,cs);
				break;
			case SYN_RCVD:
				SynRcvdHandlerFromMux(tcph,data,c);
				break;
			case ESTABLISHED:
				EstablishedHandlerFromMux(tcph,data,cs);
				break;
			case FIN_WAIT1:
				FinWait1HandlerFromMux(tcph,cs);
				break;
  			case CLOSE_WAIT:
				CloseWaitHandlerFromMux(tcph,cs);
				break;
			case CLOSING:
				ClosingHandlerFromMux(tcph,cs);
				break;
			case LAST_ACK:
				LastAckHandlerFromMux(tcph,cs);
				break;
			case FIN_WAIT2:
				FinWait2HandlerFromMux(tcph, cs);
				break;
			case TIME_WAIT:
				TimeWaitHandlerFromMux(tcph,cs);
				break;
			default:
				cout<<"Not Supported Now"<<" "<<connStat<<endl;
				break;
		  }//switch
		}//cs != clist.end()
		else{
			cout<<"CAN NOT FIND THIS CONNECTION"<<endl;
			cout<<clist.size()<<endl;
		}
      }//event.handle==mux
      if (event.handle==sock) {
	  	// handle socket request
			SockRequestResponse s;
			MinetReceive(sock,s);
			switch(s.type){
				case CONNECT:
					ConnectHandler(s);
					break;
				case ACCEPT:
					AcceptHandler(s);
					break;
				case STATUS:
					StatusHandler(s);
					break;
				case WRITE:
					WriteHandler(s);
					break;
				case CLOSE:
					CloseHandler(s);
					break;
				case FORWARD:
					break;
				default:
					cout<<"NOT SUPPORTED TYPE"<<s.type<<"\n"<<endl;
				break;
			}
		}
    }
  }
  MinetDeinit();
  return 0;
}

/*
 ********************************Request Handler***************************
 *
*/
void AcceptHandler(SockRequestResponse& s){
	cout<<"**request accept**"<<endl;
	if(clist.size() == 0){
		Connection c(s.connection.src, IP_ADDRESS_ANY,s.connection.srcport,PORT_ANY,s.connection.protocol);
		TCPState tcpState(INITSEQ, LISTEN, 0);
		ConnectionToStateMapping<TCPState> ctos;
		ctos.connection = c;
		ctos.state = tcpState;
		ctos.bTmrActive = false;
		clist.push_back(ctos);
	}
	ReplyStatus(s.connection,0);
}

void StatusHandler(SockRequestResponse& s){
	cout<<"**request status**"<<endl;
	if(s.bytes>0){
       ConnectionList<TCPState>::iterator cs = clist.FindMatching(s.connection);
        (*cs).state.RecvBuffer.Erase(0,s.bytes);
    }
}

void CloseHandler(SockRequestResponse& s){
	cout<<"**request close**"<<endl;
	ConnectionList<TCPState>::iterator it = clist.FindMatching(s.connection);
	if(it == clist.end()){
		ReplyStatus(s.connection,0, ENOMATCH);
		return ;
	}
	if((*it).state.GetState() == ESTABLISHED || (*it).state.GetState()==SYN_RCVD){
		SendFin(it);
		(*it).state.SetState(FIN_WAIT1);
	}
	else if((*it).state.GetState() == CLOSE_WAIT){
		SendFin(it);
		(*it).state.SetState(LAST_ACK);
	}
	else{
		clist.erase(it);
	}
	(*it).state.last_sent++;
}

void ConnectHandler(SockRequestResponse& s){
	cout<<"**request connect**"<<endl;
	ConnectionList<TCPState>::iterator cs = clist.FindMatching(s.connection);
	if(cs == clist.end() || (*cs).state.GetState()==LISTEN){
		Connection c1 = s.connection;
		Time t1;
		t1.SetToCurrentTime();
		t1.tv_sec += 5;
		TCPState s1(INITSEQ,SYN_SENT,10);
		s1.SetSendRwnd(4000);
		s1.SetLastRecvd(0);
		s1.last_sent = INITSEQ-1;
		s1.last_acked = INITSEQ-1;
		ConnectionToStateMapping<TCPState> ctsm(c1,t1,s1,true);
		clist.push_front(ctsm);
		cs = clist.FindMatching(c1);

	}
	else if((*cs).state.GetState() == CLOSED){
		SetConnectionTimeout(cs);
		(*cs).state.stateOfcnx = SYN_SENT;
		(*cs).bTmrActive = true;
		(*cs).state.SetSendRwnd(4000);
		(*cs).state.SetLastRecvd(0);

	}
	SendSyn(cs);
	ReplyStatus((*cs).connection,0);
}


void WriteHandler(SockRequestResponse& s){
	cout<<"**request write**"<<endl;
	ConnectionList<TCPState>::iterator it = clist.FindMatching(s.connection);
	if(it == clist.end()){
		cout<<"the connection has not been created"<<endl;
		return ;
	}
	int bufSize = (*it).state.SendBuffer.GetSize();
	int size = s.data.GetSize();
	(*it).state.SendBuffer.AddBack(s.data.ExtractFront(size));
	ReplyStatus(s.connection,size);
	SendData(it);
}

/*
 ********************************Tools Function***************************
 *
*/
bool sendBufferHasDataToSend(ConnectionList<TCPState>::iterator& it){
	int size = (*it).state.SendBuffer.GetSize();
	int acked = (*it).state.last_acked;
	int sent = (*it).state.last_sent;
	if(sent-acked < size){
		return true;
	}
	return false;
}

void getConnectionFromMux(IPHeader& ipl, TCPHeader& tcph, Connection& c){
	//Remember to reverse dest and src
	//Since this is a Packet from Down Side
	ipl.GetDestIP(c.src);
	tcph.GetDestPort(c.srcport);
	ipl.GetSourceIP(c.dest);
	tcph.GetSourcePort(c.destport);
	ipl.GetProtocol(c.protocol);
}

bool GetAndAnalyzeIPPacket(TCPHeader &tcph, Connection &c, Buffer &data) {
	Packet p;
	MinetReceive(mux,p);

	unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
	p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
	IPHeader iph=p.FindHeader(Headers::IPHeader);
	tcph=p.FindHeader(Headers::TCPHeader);

	unsigned short totlen;
	unsigned char iphlen;
	iph.GetTotalLength(totlen);
	iph.GetHeaderLength(iphlen);
	unsigned datalen = (unsigned) totlen - (unsigned) (iphlen*sizeof(int)) - tcphlen;

	if (datalen) {
		data=p.GetPayload().ExtractFront(datalen);
	}

	iph.GetDestIP(c.src);
	iph.GetSourceIP(c.dest);
	iph.GetProtocol(c.protocol);
	tcph.GetDestPort(c.srcport);
	tcph.GetSourcePort(c.destport);
	return tcph.IsCorrectChecksum(p);
}

//ResetConnection
void ResetConnection(ConnectionList<TCPState>::iterator& cs){
	cout<<"RESET CONNECTION"<<endl;
	(*cs).state.last_acked = INITSEQ-1;
	(*cs).state.last_sent = INITSEQ-1;
	(*cs).state.stateOfcnx = CLOSED;
	(*cs).bTmrActive = false;

}

Packet CreatePacket(ConnectionList<TCPState>::iterator &ptr, unsigned char flags)
{
	Packet p;
	IPHeader ih;
	TCPHeader th;

	//IP header
	ih.SetProtocol(IP_PROTO_TCP);
	ih.SetSourceIP((*ptr).connection.src);
	ih.SetDestIP((*ptr).connection.dest);

	if(IS_SYN(flags))
		ih.SetTotalLength(TCP_HEADER_BASE_LENGTH + 4 + IP_HEADER_BASE_LENGTH);
	else
		ih.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);

	p.PushHeader(ih);

	// TCP header
	th.SetSourcePort((*ptr).connection.srcport,p);
	th.SetDestPort((*ptr).connection.destport,p);

	if(IS_SYN(flags)) {
		th.SetSeqNum((*ptr).state.GetLastAcked(),p);
		//Set the MSS length for the connection
		TCPOptions opts;
		opts.len = TCP_HEADER_OPTION_KIND_MSS_LEN;
		opts.data[0] = (char) TCP_HEADER_OPTION_KIND_MSS;
		opts.data[1] = (char) TCP_HEADER_OPTION_KIND_MSS_LEN;
		opts.data[2] = (char) ((TCP_MAXIMUM_SEGMENT_SIZE & 0xFF00) >> 8);
		opts.data[3] = (char) (TCP_MAXIMUM_SEGMENT_SIZE & 0x00FF);
		th.SetOptions(opts);
	} else {
		th.SetSeqNum((*ptr).state.GetLastSent()+1,p);
	}

	th.SetFlags(flags,p);
	if(IS_ACK(flags))
		th.SetAckNum((*ptr).state.GetLastRecvd()+1,p);

	//Set the window size
	th.SetWinSize((*ptr).state.GetRwnd(),p);

	if(IS_SYN(flags)) {
		th.SetHeaderLen((TCP_HEADER_BASE_LENGTH+4)/4,p);
	}
	else {
		th.SetHeaderLen((TCP_HEADER_BASE_LENGTH/4),p);
	}
	p.PushBackHeader(th);
//	th.RecomputeChecksum(p);
	return p;
}

Packet CreatePayloadPacket(ConnectionList<TCPState>::iterator &ptr, unsigned &bytesize, unsigned int datasize, unsigned char flags)
{
//	cout<<"In createpayload "<<datasize<<" "<<endl;
  //Find number of data bytes for payload
  	bytesize = datasize;
	unsigned int wSize = (*ptr).state.last_sent - (*ptr).state.last_acked;
	cout<<(*ptr).state.last_sent<<" -- "<<(*ptr).state.last_acked<<endl;
    bytesize = MIN(datasize,(*ptr).state.GetN()-wSize);
	bytesize = MIN(bytesize,(*ptr).state.rwnd);
	bytesize = MIN(bytesize,TCP_MAXIMUM_SEGMENT_SIZE);

	char tempBuffer[TCP_MAXIMUM_SEGMENT_SIZE+1];
  (*ptr).state.SendBuffer.GetData(tempBuffer, bytesize, wSize);

  Buffer payload(tempBuffer, bytesize);
  //Create a data packet
  Packet p(payload);

  IPHeader ih;
  ih.SetProtocol(IP_PROTO_TCP);
  ih.SetSourceIP((*ptr).connection.src);
  ih.SetDestIP((*ptr).connection.dest);
  ih.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH + bytesize);
  p.PushFrontHeader(ih);

  TCPHeader th;
  th.SetSourcePort((*ptr).connection.srcport,p);
  th.SetDestPort((*ptr).connection.destport,p);
  th.SetSeqNum((*ptr).state.GetLastSent() + 1,p);

  th.SetFlags(flags,p);
  th.SetAckNum((*ptr).state.GetLastRecvd() + 1,p);

  //Set the window size
  th.SetWinSize((*ptr).state.GetRwnd(),p);
  th.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4,p);
  p.PushBackHeader(th);
  th.RecomputeChecksum(p);
  return p;
}


void ReplyWrite(Connection& c,Buffer data, int size, int err){
	SockRequestResponse repl(WRITE, c, data, size, err);
	MinetSend(sock,repl);
}

void ReplyClose(Connection& c){
	SockRequestResponse repl;
	repl.type = CLOSE;
	repl.connection = c;
	repl.bytes = 0;
	repl.error = EOK;
	MinetSend(sock,repl);
}

void SendSyn(ConnectionList<TCPState>::iterator &ptr) {
  unsigned char flags=0;
  SET_SYN(flags);
  Packet p = CreatePacket(ptr, flags);
  MinetSend(mux,p);
  //cout<<"Send Syn: (syn:ack)"<<(*ptr).state.last_sent<<" "<<(*ptr).state.last_acked<<endl;

}

void SendFin(ConnectionList<TCPState>::iterator &ptr) {
  unsigned char flags=0;
  SET_FIN(flags);
  SET_ACK(flags);
  Packet p = CreatePacket(ptr, flags);
  MinetSend(mux,p);
  //cout<<"Send Fin: (syn:ack)"<<(*ptr).state.last_sent<<" "<<(*ptr).state.last_acked<<endl;
}

void SendSynAck(ConnectionList<TCPState>::iterator &ptr) {
  unsigned char flags=0;
  SET_SYN(flags);
  SET_ACK(flags);
  Packet p = CreatePacket(ptr, flags);
MinetSend(mux,p);
//  cout<<"Send SynAck: (syn:ack)"<<(*ptr).state.last_sent<<" "<<(*ptr).state.last_acked<<endl;
}

void SendAck(ConnectionList<TCPState>::iterator &ptr) {
  unsigned char flags=0;
  SET_ACK(flags);
  Packet p = CreatePacket(ptr, flags);
  MinetSend(mux,p);
}

void SendRst(ConnectionList<TCPState>::iterator &ptr) {
  unsigned char flags=0;
  SET_RST(flags);
  SET_ACK(flags);
  Packet p = CreatePacket(ptr, flags);
  MinetSend(mux,p);
}


void SendData(ConnectionList<TCPState>::iterator &ptr) {
  	int size = (*ptr).state.SendBuffer.GetSize();
	int acked = (*ptr).state.last_acked;
	int sent = (*ptr).state.last_sent;
unsigned datasize = size - (sent-acked);
  unsigned char flags=0;
  SET_PSH(flags);
  SET_ACK(flags);

  if(datasize > 0) {
    unsigned int bytesize;
    Packet p = CreatePayloadPacket(ptr, bytesize, datasize, flags);
    cout<<"Prepare send data size: "<<bytesize<<endl;
	MinetSend(mux,p);
	(*ptr).state.last_sent += bytesize;
    IPHeader ipl=p.FindHeader(Headers::IPHeader);
    TCPHeader tcph=p.FindHeader(Headers::TCPHeader);
    //Create packets until bytesize becomes 0
    while(bytesize>0 && datasize>0) {
      datasize -= bytesize;
	if(datasize == 0)
       		 break;
	Packet p = CreatePayloadPacket(ptr, bytesize, datasize, flags);
	MinetSend(mux,p);
	TCPHeader tcph=p.FindHeader(Headers::TCPHeader);

	(*ptr).state.last_sent += bytesize;
        ipl=p.FindHeader(Headers::IPHeader);
        tcph=p.FindHeader(Headers::TCPHeader);
    }
  }
}

/*
 ********************************Timeout Handle***************************
 *
*/

void TimeoutHandler(ConnectionList<TCPState>::iterator &it){
	cout<<"Connection "<<(*it).connection<<" timeout"<<endl;
	switch((*it).state.GetState()){
		case SYN_RCVD:
			SendSynAck(it);
			SetConnectionTimeout(it);
			break;
		case ESTABLISHED:
			//GBN
			if((*it).state.SendBuffer.GetSize()){
				unsigned int ack = (*it).state.GetLastAcked();
				(*it).state.SetLastSent(ack);
				SendData(it);
			}
			else{
				SendAck(it);
			}
			SetConnectionTimeout(it);
			break;
		case LISTEN:
			break;
		case CLOSE_WAIT:
			ResetConnection(it);
			break;
		case SYN_SENT:
			if((*it).state.tmrTries == 0){
				ReplyWrite((*it).connection,(*it).state.RecvBuffer,0,(ECONN_FAILED));
				ResetConnection(it);
			}
			(*it).state.tmrTries--;
			SendSyn(it);
			SetConnectionTimeout(it);
			break;
		case LAST_ACK:
			SendFin(it);
			SetConnectionTimeout(it);
			break;
		case FIN_WAIT1:
			SendFin(it);
			SetConnectionTimeout(it);
			break;
		case CLOSING:
			SendAck(it);
			SetConnectionTimeout(it);
			break;
		case TIME_WAIT:
			ResetConnection(it);
			break;
		default:
			SetConnectionTimeout(it);
			break;
	}

}

bool IsTimeout(Time &current_time, Time &select_timeout) {
  Time zero(0,0);
  bool active=false;

  ConnectionList<TCPState>::iterator earliest = clist.FindEarliest();
  if (earliest != clist.end()) {
    if ((*earliest).timeout < current_time) {
      select_timeout = zero;
      active=true;
    }
	else{
      double t = (double)(*earliest).timeout - (double)current_time;
      select_timeout = t;
      active = true;
    }
  }
  return active;
}


/*
 ********************************State Machine Handle***************************
 *
*/
void CloseWaitHandlerFromMux(TCPHeader& th, ConnectionList<TCPState>::iterator& cs){
	cout<<"--In CloseWait--"<<endl;
	unsigned char flag;
	th.GetFlags(flag);
    	if(IS_FIN(flag)){
		SendAck(cs);
		SetConnectionTimeout(cs,30);
	}
}

void LastAckHandlerFromMux(TCPHeader& th, ConnectionList<TCPState>::iterator& cs){
	cout<<"--In LastAck--"<<endl;
	unsigned char flag;
	th.GetFlags(flag);
	unsigned int ack;
	th.GetAckNum(ack);
    	if(IS_ACK(flag) && (*cs).state.SetLastAcked(ack)){
		ResetConnection(cs);
	}
}

void ClosingHandlerFromMux(TCPHeader& th,ConnectionList<TCPState>::iterator& cs){
	cout<<"--In Closing--"<<endl;
	unsigned char flag = 0;
	th.GetFlags(flag);
	unsigned int ack = 0;
	th.GetAckNum(ack);
	if(IS_ACK(flag) && (*cs).state.SetLastAcked(ack)){
		(*cs).state.SetState(TIME_WAIT);
		SetConnectionTimeout(cs,40);
	}
	else if(IS_FIN(flag)){
		SendAck(cs);
		SetConnectionTimeout(cs);
	}
}

void FinWait1HandlerFromMux(TCPHeader& th,ConnectionList<TCPState>::iterator& cs){
	cout<<"--In FinWait1--"<<endl;
	unsigned char flag = 0;
	th.GetFlags(flag);
	unsigned int ack = 0;
	th.GetAckNum(ack);
	unsigned int seq = 0;
	th.GetSeqNum(seq);

	if(IS_FIN(flag) && !IS_ACK(flag)){
		(*cs).state.SetLastRecvd(seq);
		SendAck(cs);
		(*cs).state.SetState(CLOSING);
		SetConnectionTimeout(cs);
	}
	else if(IS_FIN(flag) && IS_ACK(flag)){
		if((*cs).state.SetLastAcked(ack)){
			(*cs).state.SetLastRecvd(seq);
			SendAck(cs);
			(*cs).state.SetState(TIME_WAIT);
			SetConnectionTimeout(cs,40);
		}
	}
	else if(IS_ACK(flag) && (*cs).state.SetLastAcked(ack) ){
		(*cs).state.SetLastRecvd(seq);
		(*cs).state.SetState(FIN_WAIT2);
		SetConnectionTimeout(cs);
	}
}

void SynSentHandlerFromMux(TCPHeader& th,ConnectionList<TCPState>::iterator& cs){
	cout<<"--In SynSent--"<<endl;
	unsigned char flag = 0;
	th.GetFlags(flag);
	unsigned int seq = 0;
	th.GetSeqNum(seq);
	unsigned int ack = 0;
	th.GetAckNum(ack);
	unsigned short win;
	th.GetWinSize(win);
	if(IS_SYN(flag) && IS_ACK(flag) && (*cs).state.SetLastAcked(ack)){
		(*cs).state.SetLastRecvd(seq);
		(*cs).state.SetSendRwnd(win);
		SendAck(cs);
		(*cs).state.SetState(ESTABLISHED);
		ReplyWrite((*cs).connection,(*cs).state.RecvBuffer,0,EOK);
	}
}

void EstablishedHandlerFromMux(TCPHeader& th,Buffer& data,ConnectionList<TCPState>::iterator& cs){
	cout<<"--In Established--"<<endl;
    unsigned char flag = 0;
    th.GetFlags(flag);
    unsigned int ack = 0;
    th.GetAckNum(ack);
    unsigned int seq = 0;
    th.GetSeqNum(seq);

    if(IS_ACK(flag) && IS_FIN(flag)){
		if((*cs).state.SetLastAcked(ack)){
			(*cs).state.SetState(CLOSE_WAIT);
			(*cs).state.SetLastRecvd(seq);
            SockRequestResponse repl(CLOSE, (*cs).connection, data, (*cs).state.RecvBuffer.GetSize(), EOK);
			MinetSend(sock,repl);
			SetConnectionTimeout(cs,20);
			SendAck(cs);
		}
	}
	else if(IS_ACK(flag)){
		if((*cs).state.SetLastAcked(ack)){
			if(data.GetSize()){
				if(!(*cs).state.SetLastRecvd(seq,data.GetSize())){
					SendAck(cs);
					return;
				}
				(*cs).state.RecvBuffer.AddBack(data);
				ReplyWrite((*cs).connection,(*cs).state.RecvBuffer,(*cs).state.RecvBuffer.GetSize(), EOK);
				SendAck(cs);
			}//GetSize
		}//If SetLastAcked
	}//Is_ACK
}

void FinWait2HandlerFromMux(TCPHeader& th,ConnectionList<TCPState>::iterator& cs){
	cout<<"--In FinWait2--"<<endl;
	unsigned char flag = 0;
	th.GetFlags(flag);
	unsigned int ack = 0;
	th.GetAckNum(ack);
	unsigned int seq = 0;
	th.GetSeqNum(seq);

	if(IS_FIN(flag)){
		(*cs).state.SetLastRecvd(seq);
		SendAck(cs);
		(*cs).state.SetState(TIME_WAIT);
		SetConnectionTimeout(cs,40);
	}
}

void TimeWaitHandlerFromMux(TCPHeader& th,ConnectionList<TCPState>::iterator& cs){
	cout<<"--In Timewait--"<<endl;
	unsigned char flag = 0;
	th.GetFlags(flag);
	unsigned int ack = 0;
	th.GetAckNum(ack);

	if(IS_FIN(flag) || IS_ACK(flag)){
		SendAck(cs);
		SetConnectionTimeout(cs,40);
	}
	else if(IS_FIN(flag) && IS_ACK(flag)){
		if((*cs).state.SetLastAcked(ack)){
			SendAck(cs);
			SetConnectionTimeout(cs,40);
		}
	}
	else{
	}

}

void ListenHandlerFromMux(TCPHeader &tcph, Connection& c){
	cout<<"--In LISTEN--"<<endl;
	unsigned char flag = 0;
	tcph.GetFlags(flag);
	unsigned int seq0;
	tcph.GetSeqNum(seq0);

	if(IS_SYN(flag)){
		ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
		if(cs == clist.end()){
			return ;
		}
		else if( (*cs).state.GetState() == CLOSED){
			SetConnectionTimeout(cs);
			(*cs).state.stateOfcnx = SYN_RCVD;
			(*cs).bTmrActive = true;
			(*cs).state.SetSendRwnd(4000);
			(*cs).state.SetLastRecvd(seq0);
		}
		else if( (*cs).state.GetState() == LISTEN ){
			Connection c1 = c;
			Time t1;
			t1.SetToCurrentTime();
			t1.tv_sec += 5;
			TCPState s1(INITSEQ,SYN_RCVD,10);
			unsigned short win;
			tcph.GetWinSize(win);
			s1.SetSendRwnd(win);
			s1.SetLastRecvd(seq0);

			ConnectionToStateMapping<TCPState> ctsm(c1,t1,s1,true);
			clist.push_front(ctsm);
			cs = clist.FindMatching(c);
		}
		SendSynAck(cs);
	}
}

//In SYN_RCVD state, we expect an ACK to our SYN_ACK packet
void SynRcvdHandlerFromMux(TCPHeader& th,Buffer& data,Connection& c){
	cout<<"--In Syn_Rcvd-- "<<endl;
	unsigned char flag = 0;
	th.GetFlags(flag);
	ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);

	if(IS_ACK(flag)){
		if(cs == clist.end()){
			cout<<"Can not find this connection"<<endl;
			return ;
		}
		unsigned int seq0;
		th.GetSeqNum(seq0);
		unsigned int ack;
		th.GetAckNum(ack);
		if((*cs).state.SetLastAcked(ack)){
			if(data.GetSize()){
				(*cs).state.SetLastRecvd(seq0,data.GetSize());
				(*cs).state.RecvBuffer.AddBack(data);
			}
			(*cs).state.stateOfcnx = ESTABLISHED;
			SetConnectionTimeout(cs);
			(*cs).bTmrActive = true;

			ReplyWrite(c,(*cs).state.RecvBuffer,0,EOK);
			cout<<"reply to socket "<<0<<endl;
        }
	}
}

void ClosedHandlerFromMux(TCPHeader& th,ConnectionList<TCPState>::iterator& cs){
	cout<<"--Closed--"<<endl;
	(*cs).state.stateOfcnx = LISTEN;
	(*cs).bTmrActive = false;
}
