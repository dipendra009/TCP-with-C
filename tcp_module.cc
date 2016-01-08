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
#include "ip.h"
#include "tcpstate.h"
#include "tcp.h"
#include "buffer.h"
#include "constate.h"
#include "packet_queue.h"

#define INITSEQ 1234


using std::cout;
using std::endl;
using std::cerr;
using std::string;

MinetHandle mux, sock;
ConnectionList<TCPState> connList;

Packet CreatePacket(ConnectionList<TCPState>::iterator &connL, unsigned char flags);
void SendStatus(Connection &conn, int repLen, int);
void SendData(ConnectionList<TCPState>::iterator &connL);
void HandleTimeout(ConnectionList<TCPState>::iterator &connList);
void ResetConnection(ConnectionList<TCPState>::iterator &connL);
void SetConnectionTimeout(ConnectionList<TCPState>::iterator &connL, int inc);
void SetCongestionParameters(TCPState &state);
void CongestionControl(ConnectionList<TCPState>::iterator &connL);
void CongestionControlTimeOut(ConnectionList<TCPState>::iterator &connL);
void CongestionControlTripAck(ConnectionList<TCPState>::iterator &connL);


int main(int argc, char *argv[])
{
  MinetInit(MINET_TCP_MODULE);
  cout<<"in main..."<<endl;
  MinetSendToMonitor(MinetMonitoringEvent("Can connect to mux"));

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


  Time currentTime, selectTimeOut;
  Time zero(0,0);


  while(1)
  {
  	int retValue;
	bool timerActive = false;

	gettimeofday(&currentTime, 0);

	ConnectionList<TCPState>::iterator firstConn = connList.FindEarliest();
	if(firstConn != connList.end())
	{
		if(firstConn->timeout < currentTime)
		{
			selectTimeOut = zero;
			timerActive = true;
		}
		else
		{
			selectTimeOut = (double)(firstConn->timeout) - (double)currentTime;
			timerActive = true;
		}
	}

	if (timerActive == false)
	{
		retValue = MinetGetNextEvent(event);
	}
	else if((double)selectTimeOut == 0.0)
	{
		event.eventtype = MinetEvent::Timeout;

	}
	else
	{
		retValue = MinetGetNextEvent(event, (double)selectTimeOut);
	}

	if(retValue < 0)
	{
		cerr<<"Error in next event"<<endl;
		while(1);
	}
	else if(event.eventtype==MinetEvent::Timeout)
	{
		cout<<"Connection timeout event"<<endl;
		ConnectionList<TCPState>::iterator connL = connList.FindEarliest();



		while((connL != connList.end())&&(connL->timeout < currentTime))
		{
			CongestionControlTimeOut(connL);
			gettimeofday(&currentTime, 0);
			HandleTimeout(connL);
			connL = connList.FindEarliest();

		}
	}

    // if we received an unexpected type of event, print error
    else if (event.eventtype!=MinetEvent::Dataflow
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
     }


	else {
	
      //  Data from the IP layer below  //
	if (event.handle==mux) {
	Packet p;
	MinetReceive(mux,p);
	Connection conn;
	Buffer data;
	TCPHeader tcph;
	unsigned short totalLen;
	unsigned char iphlen;
	unsigned datalen;
	unsigned int seqNum;
	unsigned int ackNum;
	unsigned char flags = 0;
	unsigned short winSize;
	unsigned tcphLen;

	tcphLen = TCPHeader::EstimateTCPHeaderLength(p);
	p.ExtractHeaderFromPayload<TCPHeader>(tcphLen);
	IPHeader iph = p.FindHeader(Headers::IPHeader);
	tcph = p.FindHeader(Headers::TCPHeader);
	iph.GetTotalLength(totalLen);
	iph.GetHeaderLength(iphlen);
	datalen = (unsigned)totalLen -(unsigned)(iphlen*4) - tcphLen;
	if(datalen)
	{
		data = p.GetPayload().ExtractFront(datalen);
	}

	iph.GetDestIP(conn.src);
	iph.GetSourceIP(conn.dest);
	tcph.GetDestPort(conn.srcport);
	tcph.GetSourcePort(conn.destport);
	iph.GetProtocol(conn.protocol);

	tcph.GetAckNum(ackNum);
	tcph.GetSeqNum(seqNum);
	tcph.GetFlags(flags);
	tcph.GetWinSize(winSize);


	ConnectionList<TCPState>::iterator connL = connList.FindMatching(conn);

	CongestionControl(connL);

	if(connL != connList.end())
	{
		unsigned int connState;
		connState =  connL->state.GetState();

		if(IS_RST(flags))

		{
			if(connL->bTmrActive == false)
				continue;
			else
			{
				ResetConnection(connL);
				continue;
			}
		}

		connL->state.SetSendRwnd(winSize);
		
		switch (connState)
		{
			case CLOSED:
				cout<<"in closed"<<endl;		 
				break;

			case LISTEN:
		 		if(IS_SYN(flags))
				{
					Connection con = conn;
					Time ttime;
					ttime.SetToCurrentTime();
					ttime.tv_sec+=5;
					TCPState sstate1(INITSEQ, SYN_RCVD,8);
					sstate1.SetSendRwnd(winSize);
					sstate1.SetLastRecvd(seqNum);
					ConnectionToStateMapping<TCPState> connStateMap(con, ttime,sstate1,true);
					connList.push_front(connStateMap);
					connL = connList.FindMatching(con);

					flags = 0;
					SET_SYN(flags);
					SET_ACK(flags);
					p = CreatePacket(connL, flags);
					MinetSend(mux,p);
				}

				break;

			case SYN_SENT:
				cout<<"in syn_sent..."<<endl;
				if(IS_SYN(flags)&&IS_ACK(flags))
				{
					connL->state.SetLastAcked(ackNum);
					connL->state.SetSendRwnd(winSize);
					flags = 0;
					SET_ACK(flags);
					p = CreatePacket(connL, flags);
					MinetSend(mux,p);
					connL->state.SetState(ESTABLISHED);
					SockRequestResponse reply(WRITE, connL->connection, connL->state.RecvBuffer, 0, EOK);
					MinetSend(sock, reply);

				}

				break;

			case SYN_RCVD:
				cout<<"in syn_rcvd..."<<endl;
				if(IS_ACK(flags))
				{
					connL->state.SetLastAcked(ackNum);
					if(data.GetSize())
					{
						connL->state.SetLastRecvd(seqNum, data.GetSize());
						connL->state.RecvBuffer.AddBack(data);
					}
					connL->state.stateOfcnx = ESTABLISHED;
					SetConnectionTimeout(connL,5);
					connL->bTmrActive = true;
					SockRequestResponse reply(WRITE, connL->connection, connL->state.RecvBuffer, 0, EOK);
					MinetSend(sock, reply);

				}

				break;

			case ESTABLISHED:
				cout<<"in established"<<endl;
				if(IS_ACK(flags) && (IS_FIN(flags)))
				{
					connL->state.SetLastAcked(ackNum);
					connL->state.SetState(CLOSE_WAIT);
					connL->state.SetLastRecvd(seqNum);
					SockRequestResponse reply(CLOSE, connL->connection, data, connL->state.RecvBuffer.GetSize(),EOK);
					MinetSend(sock, reply);
					SetConnectionTimeout(connL,20);
					flags = 0;
					SET_ACK(flags);
					p = CreatePacket(connL, flags);
					MinetSend(mux,p);
				}
				else if((IS_ACK(flags))&&(connL->state.SetLastAcked(ackNum)))
				{
					;
					if(data.GetSize())
					{
						if(connL->state.SetLastRecvd(seqNum, data.GetSize()))
						{

							connL->state.RecvBuffer.AddBack(data);
							SockRequestResponse reply(WRITE, connL->connection, connL->state.RecvBuffer, connL->state.RecvBuffer.GetSize(), EOK);
							MinetSend(sock, reply);

						}
						flags = 0;
						SET_ACK(flags);
						p = CreatePacket(connL, flags);
						MinetSend(mux,p);


					}
				}
				break;

			case FIN_WAIT1:
				cout<<"in fin-wait1..."<<endl;
				if(IS_FIN(flags)&&!(IS_ACK(flags)))
				{
					connL->state.SetLastRecvd(seqNum);
					flags = 0;
					SET_ACK(flags);
					p = CreatePacket(connL, flags);
					MinetSend(mux, p);
					connL->state.SetState(CLOSING);
					SetConnectionTimeout(connL,40);
					
				}
				else if(IS_FIN(flags)&&IS_ACK(flags))
				{
					if(connL->state.SetLastAcked(ackNum))
					{
						connL->state.SetLastRecvd(seqNum);
						flags = 0;
						SET_ACK(flags);
						p = CreatePacket(connL, flags);
						MinetSend(mux, p);
						connL->state.SetState(TIME_WAIT);
						SetConnectionTimeout(connL, 40);
					}
				}
				else if(IS_ACK(flags)&&(connL->state.SetLastAcked(ackNum)))
				{
					connL->state.SetLastRecvd(seqNum);
					
					connL->state.SetState(FIN_WAIT2);
					SetConnectionTimeout(connL, 40);
					
				}
				break;

			case FIN_WAIT2:
				cout<<"in fin_wait2..."<<endl;
				if(IS_FIN(flags))
				{
					connL->state.SetLastRecvd(seqNum);
					flags = 0;
					SET_ACK(flags);
					p = CreatePacket(connL, flags);
					MinetSend(mux, p);
					connL->state.SetState(TIME_WAIT);
					SetConnectionTimeout(connL,40);
					
				}

				break;

			case CLOSE_WAIT:
				cout<<"in close_wait..."<<endl;
				break;

			case CLOSING:
				cout<<"in closing..."<<endl;
				if(IS_ACK(flags)&&(connL->state.SetLastAcked(ackNum)))
				{
					connL->state.SetState(TIME_WAIT);
					SetConnectionTimeout(connL,40);
				}
		 		break;

			case LAST_ACK:
				cout<<"in lastack..."<<endl;
				if(IS_ACK(flags)&&(connL->state.SetLastAcked(ackNum)))
				{
					ResetConnection(connL);
				}
			 	break;


			case TIME_WAIT:
				cout<<"timewait"<<endl;	
			 	break;

			default:
				cout<<"In default of mux"<<endl;


		}


	}



	}

      //  Data from the Sockets layer above  //
      if (event.handle==sock) {
	SockRequestResponse s;
	MinetReceive(sock,s);
 	unsigned char flag=0;
	Packet p;

	switch (s.type) 
	{

		case CONNECT:
		{
			cout<<"request connect..."<<endl;
			ConnectionList<TCPState>::iterator connL = connList.FindMatching(s.connection);
			if (connL == connList.end() || connL->state.GetState()==LISTEN)
			{
				Connection conn = s.connection;
				Time time1;
				time1.SetToCurrentTime();
				time1.tv_sec += 5;
				TCPState state(INITSEQ, SYN_SENT, 10);
				state.SetSendRwnd(5000);
				state.SetLastRecvd(0);
				state.SetLastSent(INITSEQ-1);
				state.SetLastAcked(INITSEQ-1);
				ConnectionToStateMapping<TCPState> connStateMapp(conn, time1, state, true);
				connList.push_front(connStateMapp);
				connL = connList.FindMatching(conn);
			}
			else if(connL->state.GetState() == CLOSED)
			{
				SetConnectionTimeout(connL,5);
				connL->state.SetState(SYN_SENT);
				connL->bTmrActive = true;
				connL->state.SetSendRwnd(5000);
				connL->state.SetLastRecvd(0);

			}
			else
			{}

			SetCongestionParameters(connL->state);
			SET_SYN(flag);
			p = CreatePacket(connL, flag);
			MinetSend(mux, p);
 			SendStatus((*connL).connection, 0, EOK);
			break;
		}
	  	case ACCEPT:
		{
			cout << "request accept"<< endl;
			if(connList.size() == 0)
			{
				Connection conn(s.connection.src, IP_ADDRESS_ANY, s.connection.srcport, PORT_ANY, s.connection.protocol);
				TCPState tcpState(INITSEQ, LISTEN, 0);
				SetCongestionParameters(tcpState);
				ConnectionToStateMapping<TCPState> connToStateMap;
				connToStateMap.connection = conn;
				connToStateMap.state = tcpState;
				connToStateMap.bTmrActive = false;
				connList.push_back(connToStateMap);
			}

			SendStatus(s.connection, 0, EOK);
			break;
		}

		case WRITE:
		{
			cout<<"request write......."<<endl;
			ConnectionList<TCPState>::iterator connL = connList.FindMatching(s.connection);
			if(connL == connList.end())
			{
				cout <<"No such connection exist"<<endl;

			}
			else
			{
				int size = s.data.GetSize(); 
				connL->state.SendBuffer.AddBack(s.data.ExtractFront(size));
				SendStatus(s.connection, size, EOK);
				SendData(connL);
			}


			break;
		}
		case FORWARD:
			SendStatus(s.connection, 0, 0);
			break;
	  	case CLOSE:
		{
			cout<<"request close..."<<endl;
			ConnectionList<TCPState>::iterator connL = connList.FindMatching(s.connection);
			if(connL == connList.end())
			{
				SendStatus(s.connection, 0 , ENOMATCH);

			}
			else
			{
				SET_FIN(flag);
				SET_ACK(flag);
				p = CreatePacket(connL, flag);

				if(connL->state.GetState() == ESTABLISHED || connL->state.GetState() == SYN_RCVD)
				{
					MinetSend(mux, p);
					connL->state.SetState(FIN_WAIT1);
				}
				else if(connL->state.GetState() == CLOSE_WAIT)
				{
					MinetSend(mux, p);

					connL->state.SetState(LAST_ACK);
				}
				else
				{
					connList.erase(connL);
				}

				connL->state.last_sent++;
			}


			break;
		}
		case STATUS:
		{
			cout << "request status"<<endl;
			ConnectionList<TCPState>::iterator connL = connList.FindMatching(s.connection);
			if(s.bytes > 0)
				connL->state.RecvBuffer.Erase(0, s.bytes);

			break;
		}
		default:
	  	{

	  		cout <<"request default..."<<endl;
	    		SockRequestResponse repl;
 	   		repl.type=STATUS;
	   		repl.error=EWHAT;
	   		MinetSend(sock,repl);
	  	}
 
	}
      }
    }
  }
  MinetDeinit();
  return 0;
}

/**********************Some Helper Functions************************/


Packet CreatePacket(ConnectionList<TCPState>::iterator &connL, unsigned char flags)
{
	Packet p;
	IPHeader iph;
	TCPHeader tcph;

	// Setting IP Header
	iph.SetProtocol(IP_PROTO_TCP);
	iph.SetSourceIP(connL->connection.src);
	iph.SetDestIP(connL->connection.dest);

	iph.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);
	p.PushFrontHeader(iph);

	// Setting TCP Header

	tcph.SetSourcePort(connL->connection.srcport, p);
	tcph.SetDestPort(connL->connection.destport, p);

	tcph.SetSeqNum(connL->state.GetLastSent()+1, p);
	 
	tcph.SetFlags(flags, p);
	if(IS_ACK(flags))
	{
		tcph.SetAckNum(connL->state.GetLastRecvd()+1, p);
	}
	tcph.SetWinSize(connL->state.GetRwnd(), p);
 	tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4, p);
 
	p.PushBackHeader(tcph);

	return p;

}



void SendStatus(Connection &conn, int repLen, int error)
{
	SockRequestResponse s;
	s.type = STATUS;
	s.connection = conn;
	s.bytes = repLen;
	s.error = error;
	MinetSend(sock, s);

}

void SendData(ConnectionList<TCPState>::iterator &connL)
{
	int size = connL->state.SendBuffer.GetSize();
	int acked = connL->state.last_acked;
	int sent = connL->state.last_sent;

	unsigned dataSize = size - (sent - acked);
	unsigned char flags = 0;
	SET_ACK(flags);

	unsigned byteSize;
	byteSize =dataSize;

	while ((dataSize > 0)&&(byteSize > 0))
	{

		// Go Back N
		unsigned int wSize = connL->state.last_sent - connL->state.last_acked;
		byteSize = (dataSize < connL->state.GetN()-wSize) ? dataSize: connL->state.GetN()-wSize;

		//Congestion Control
		byteSize = (byteSize+wSize < connL->state.congWindow) ? byteSize : connL->state.congWindow-wSize;


		// Flow Control(byteSize+wSize is the total unacked bytes which must be less than recvWindow)
		byteSize = (byteSize+wSize < connL->state.rwnd) ? byteSize : connL->state.rwnd-wSize;

		cout<<"cw"<<connL->state.congWindow<<endl<<connL->state.congThreshold<<endl<<connL->state.rwnd<<endl<<byteSize;

		byteSize = (byteSize < TCP_MAXIMUM_SEGMENT_SIZE) ? byteSize : TCP_MAXIMUM_SEGMENT_SIZE;

		char tempBuffer[TCP_MAXIMUM_SEGMENT_SIZE + 1];
		connL->state.SendBuffer.GetData(tempBuffer, byteSize, wSize);
		Buffer payloadData(tempBuffer, byteSize);
		Packet p(payloadData);
		
		IPHeader iph;
		iph.SetProtocol(IP_PROTO_TCP);
		iph.SetSourceIP(connL->connection.src);
		iph.SetDestIP(connL->connection.dest);
		iph.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH + byteSize);
		p.PushFrontHeader(iph);

		TCPHeader tcph;
		tcph.SetSourcePort(connL->connection.srcport, p);
		tcph.SetDestPort(connL->connection.destport, p);
		tcph.SetSeqNum(connL->state.GetLastSent() + 1, p);
		tcph.SetAckNum(connL->state.GetLastRecvd() + 1, p);
		tcph.SetFlags(flags, p);

		//TCP FlowControl
		tcph.SetWinSize(connL->state.GetRwnd(), p);

		tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4, p);

		p.PushBackHeader(tcph);
		MinetSend(mux,p);
		connL->state.last_sent = connL->state.last_sent + byteSize;
		dataSize -= byteSize;


	}


}

void HandleTimeout(ConnectionList<TCPState>::iterator &connL)
{
	unsigned char flags = 0;
	Packet p;
	switch(connL->state.GetState())
	{
		case SYN_RCVD:
			{
			SET_SYN(flags);
			SET_ACK(flags);
			p = CreatePacket(connL, flags);
			MinetSend(mux,p);
			SetConnectionTimeout(connL,5);
			break;
			}
		case ESTABLISHED:
			//Go Back-N
			if(connL->state.SendBuffer.GetSize())
			{
				unsigned int ackNum = connL->state.GetLastAcked();
				connL->state.SetLastSent(ackNum);
				SendData(connL);
			}
			else
			{
				SET_ACK(flags);
				p = CreatePacket(connL, flags);
				MinetSend(mux,p);

			}
			SetConnectionTimeout(connL,5);
			break;

		case LISTEN:
			break;

		case CLOSE_WAIT:
			ResetConnection(connL);
			break;

		case SYN_SENT:
		{
			if(connL->state.tmrTries == 0)
			{
				SockRequestResponse reply(WRITE, connL->connection, connL->state.RecvBuffer, 0, (ECONN_FAILED));
				MinetSend(sock, reply);
 				ResetConnection(connL);
			}
			connL->state.tmrTries--;
			
			SET_SYN(flags);
			p = CreatePacket(connL, flags);
			MinetSend(mux,p);

			SetConnectionTimeout(connL,5);

			break;
		}
		case LAST_ACK:
		{
			SET_FIN(flags);
			//SET_ACK(flags);
			p = CreatePacket(connL, flags);
			MinetSend(mux,p);
			
			SetConnectionTimeout(connL,5);

			break;
		}
		case FIN_WAIT1:
			SET_FIN(flags);
			//SET_ACK(flags);
			p = CreatePacket(connL, flags);
			MinetSend(mux,p);
			SetConnectionTimeout(connL,5);
			break;

		case CLOSING:
			SET_ACK(flags);
			p = CreatePacket(connL, flags);
			MinetSend(mux,p);
			SetConnectionTimeout(connL,5);

			break;

		case TIME_WAIT:
			ResetConnection(connL);
			break;

		default:
			SetConnectionTimeout(connL,5);
			break;

	}

}
void SetConnectionTimeout(ConnectionList<TCPState>::iterator &connL, int inc)
{
	connL->timeout.SetToCurrentTime();
	connL->timeout.tv_sec+=inc;
}

void ResetConnection(ConnectionList<TCPState>::iterator &connL)
{
	connL->state.last_acked = INITSEQ - 1;
	connL->state.last_sent = INITSEQ - 1;
	connL->state.stateOfcnx = CLOSED;
	connL->bTmrActive = false;
}

// Congestion Control mechanism
void CongestionControl(ConnectionList<TCPState>::iterator &connL)
{
	if(connL->state.GetLastAcked() != connL->state.lastAcked)
	{
		//Slow Start
		if(connL->state.congWindow < connL->state.congThreshold)
			connL->state.congWindow += TCP_MAXIMUM_SEGMENT_SIZE;
		// Congestion Avoidance
		else
			connL->state.congWindow += TCP_MAXIMUM_SEGMENT_SIZE*TCP_MAXIMUM_SEGMENT_SIZE/(connL->state.congWindow);

	}
	else
		connL->state.duplicateAck++;
	if(connL->state.duplicateAck >= 3)
		CongestionControlTripAck(connL);


}
//Handle Timeout in Congestion Control
void CongestionControlTimeOut(ConnectionList<TCPState>::iterator &connL)
{
	connL->state.congWindow = TCP_MAXIMUM_SEGMENT_SIZE;
	connL->state.congThreshold = connL->state.congWindow/2;
	connL->state.lastAcked = connL->state.GetLastAcked();
	connL->state.duplicateAck = 0;


}
//Handle Triple Ack in Congestion Control
void CongestionControlTripAck(ConnectionList<TCPState>::iterator &connL)
{

	// Congestion Control on Triple Ack
	connL->state.congThreshold = connL->state.congWindow/2;
	connL->state.congWindow = connL->state.congThreshold + 3*TCP_MAXIMUM_SEGMENT_SIZE;

	connL->state.lastAcked = connL->state.GetLastAcked();
	connL->state.duplicateAck = 0;


}

// Set initial Congestion Parameters for each connections
void SetCongestionParameters(TCPState &state)
{
		// Congestion Slow Start
		state.congWindow = TCP_MAXIMUM_SEGMENT_SIZE;
		state.congThreshold = 64*TCP_MAXIMUM_SEGMENT_SIZE;
		state.lastAcked = state.GetLastAcked();
		state.duplicateAck = 0;

}

/*******************************************************************/
