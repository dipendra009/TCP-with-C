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

Packet CreatePacket(ConnectionList<TCPState>::iterator &ptr, unsigned char flags);
void ReplyStatus(Connection &conn, int replen, int);
void SendData(ConnectionList<TCPState>::iterator &cs);
void TimeoutHandler(ConnectionList<TCPState>::iterator &connlist);
void ResetConnection(ConnectionList<TCPState>::iterator &cs);
void SetConnectionTimeout(ConnectionList<TCPState>::iterator &cs, int inteval=4);


int main(int argc, char *argv[])
{
  bool timerActive = false;
  MinetInit(MINET_TCP_MODULE);
  cout<<"in main..."<<endl;
  MinetSendToMonitor(MinetMonitoringEvent("Can connect to mux"));

  ConnectionList<TCPState> connlist;

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
  	int rc;
	cout<<"in while"<<endl;
	gettimeofday(&currentTime, 0);

	ConnectionList<TCPState>::iterator earliest = connlist.FindEarliest();
	if(earliest != connlist.end())
	{
		if(earliest->timeout < currentTime)
		{
			selectTimeOut = zero;
			timerActive = true;
		}
		else
		{
			selectTimeOut = (double)(earliest->timeout) - (double)currentTime;
			timerActive = true;
		}
	}

	if (timerActive == false)
	{
		rc = MinetGetNextEvent(event);
	}
	else if((double)selectTimeOut == 0.0)
	{
		event.eventtype = MinetEvent::Timeout;

	}
	else
	{
		rc = MinetGetNextEvent(event, (double)selectTimeOut);
		cout<<"rc"<<rc<<endl;
	}

	if(rc < 0)
	{
		cerr<<"Error in next event"<<endl;
		while(1);
	}
	else if(event.eventtype==MinetEvent::Timeout)
	{
		cout<<"Connection timeout event"<<endl;
		ConnectionList<TCPState>::iterator cs = connlist.FindEarliest();
		while((cs != connlist.end())&&(cs->timeout < currentTime))
		{
			gettimeofday(&currentTime, 0);
			TimeoutHandler(cs);
			cs = connlist.FindEarliest();

		}
	}

    // if we received an unexpected type of event, print error
    else if (event.eventtype!=MinetEvent::Dataflow
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    }


	else {
	
      //  Data from the IP layer below  //
	if (event.handle==mux) {
	cout<<"in mux...."<<endl;
	Packet p;
	MinetReceive(mux,p);
	Connection conn;
	Buffer data;
	TCPHeader tcph;
	unsigned tcphlen = TCPHeader::EstimateTCPHeaderLength(p);
	p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
	IPHeader iph = p.FindHeader(Headers::IPHeader);
	tcph = p.FindHeader(Headers::TCPHeader);
	unsigned short totallen;
	unsigned char iphlen;
	iph.GetTotalLength(totallen);
	iph.GetHeaderLength(iphlen);
	unsigned datalen;
	datalen = (unsigned)totallen -(unsigned)(iphlen*sizeof(int)) - tcphlen;
	if(datalen)
	{
		data = p.GetPayload().ExtractFront(datalen);
	}

	iph.GetDestIP(conn.src);
	iph.GetSourceIP(conn.dest);
	iph.GetProtocol(conn.protocol);
	tcph.GetDestPort(conn.srcport);
	tcph.GetSourcePort(conn.destport);
	unsigned int seqNum;
	unsigned int ackNum;
	tcph.GetAckNum(ackNum);
	tcph.GetSeqNum(seqNum);
	unsigned char flags = 0;
	tcph.GetFlags(flags);
	unsigned short window;
	tcph.GetWinSize(window);
	//Packet p;
	cout<<"conn"<<conn<<endl;


	ConnectionList<TCPState>::iterator cs = connlist.FindMatching(conn);
cout<<"cs"<<cs<<endl;
	if(cs != connlist.end())
	{
		unsigned int connState = cs->state.GetState();

		cout<<"connState"<<connState<<endl;
		if(IS_RST(flags))

		{
			if(cs->bTmrActive == false)
				continue;
			else
			{
				ResetConnection(cs);
				continue;
			}
		}

		cs->state.SetSendRwnd(window);
		cout<<"switching"<<endl;
		switch (connState)
		{
			case CLOSED:
				cout<<"in closed..."<<endl;
				if(IS_SYN(flags))
				{
					SetConnectionTimeout(cs);
					cs->state.stateOfcnx = SYN_RCVD;
					cs->bTmrActive = true;
					cs->state.SetSendRwnd(5000);
					cs->state.SetLastRecvd(seqNum);
					flags = 0;
					SET_SYN(flags);
					SET_ACK(flags);
					p = CreatePacket(cs, flags);
					MinetSend(mux,p);
				}

				break;

			case LISTEN:
				cout<<"in listen..."<<endl;
				if(IS_SYN(flags))
				{
					Connection con = conn;
					Time ttime;
					ttime.SetToCurrentTime();
					ttime.tv_sec+=5;
					TCPState sstate1(INITSEQ, SYN_RCVD,10);
					sstate1.SetSendRwnd(window);
					sstate1.SetLastRecvd(seqNum);

					ConnectionToStateMapping<TCPState> connStateMap(con, ttime,sstate1,true);
					connlist.push_front(connStateMap);
					cs = connlist.FindMatching(con);

					flags = 0;
					SET_SYN(flags);
					SET_ACK(flags);
					Packet p = CreatePacket(cs, flags);
					MinetSend(mux,p);
				}

				break;

			case SYN_SENT:
				cout<<"in syn_sent..."<<endl;
				if(IS_SYN(flags)&&IS_ACK(flags))
				{
					cs->state.SetLastAcked(ackNum);
					cs->state.SetSendRwnd(window);
					flags = 0;
					SET_ACK(flags);
					Packet p = CreatePacket(cs, flags);
					MinetSend(mux,p);
					cs->state.SetState(ESTABLISHED);
					SockRequestResponse reply(WRITE, cs->connection, cs->state.RecvBuffer, 0, EOK);
					MinetSend(sock, reply);

				}

				break;
			case SYN_RCVD:
				cout<<"in syn_rcvd..."<<endl;
				if(IS_ACK(flags))
				{
					cs->state.SetLastAcked(ackNum);
					if(data.GetSize())
					{
						cs->state.SetLastRecvd(seqNum, data.GetSize());
						cs->state.RecvBuffer.AddBack(data);
					}
					cs->state.stateOfcnx = ESTABLISHED;
					SetConnectionTimeout(cs);
					cs->bTmrActive = true;
					SockRequestResponse reply(WRITE, cs->connection, cs->state.RecvBuffer, 0, EOK);
					MinetSend(sock, reply);

				}

				break;

			case ESTABLISHED:
				cout<<"in established"<<endl;
				if(IS_ACK(flags) && (IS_FIN(flags)))
				{
					cs->state.SetLastRecvd(ackNum);
					cs->state.SetState(CLOSE_WAIT);
					cs->state.SetLastRecvd(seqNum);
					SockRequestResponse reply(CLOSE, cs->connection, data, cs->state.RecvBuffer.GetSize(),EOK);
					MinetSend(sock, reply);
					SetConnectionTimeout(cs,20);
					flags = 0;
					SET_ACK(flags);
					Packet p = CreatePacket(cs, flags);
					MinetSend(mux,p);
				}
				else if(IS_ACK(flags))
				{
					cs->state.SetLastAcked(ackNum);
					if(data.GetSize())
					{
						if(cs->state.SetLastRecvd(seqNum, data.GetSize()))
						{

							cs->state.RecvBuffer.AddBack(data);
							SockRequestResponse reply(WRITE, cs->connection, cs->state.RecvBuffer, cs->state.RecvBuffer.GetSize(), EOK);
							MinetSend(sock, reply);

						}
						flags = 0;
						SET_ACK(flags);
						Packet p = CreatePacket(cs, flags);
						MinetSend(mux,p);


					}
				}
				break;

			case FIN_WAIT1:
				cout<<"in fin-wait1..."<<endl;
				if(IS_FIN(flags)&&!(IS_ACK(flags)))
				{
					cs->state.SetLastRecvd(seqNum);
					flags = 0;
					SET_ACK(flags);
					Packet p = CreatePacket(cs, flags);
					MinetSend(mux, p);
					cs->state.SetState(CLOSING);
					SetConnectionTimeout(cs,40);
				}
				else if(IS_FIN(flags)&&IS_ACK(flags))
				{
					if(cs->state.SetLastAcked(ackNum))
					{
						cs->state.SetLastRecvd(seqNum);
						flags = 0;
						SET_ACK(flags);
						Packet p = CreatePacket(cs, flags);
						MinetSend(mux, p);
						cs->state.SetState(TIME_WAIT);
						SetConnectionTimeout(cs, 40);
					}
				}
				else if(IS_ACK(flags)&&(cs->state.SetLastAcked(ackNum)))
				{
					cs->state.SetLastRecvd(seqNum);
					cs->state.SetState(FIN_WAIT2);
					SetConnectionTimeout(cs, 40);
				}
				break;

			case FIN_WAIT2:
				cout<<"in fin_wait2..."<<endl;
				if(IS_FIN(flags))
				{
					cs->state.SetLastRecvd(seqNum);
					flags = 0;
					SET_ACK(flags);
					Packet p = CreatePacket(cs, flags);
					MinetSend(mux, p);
					cs->state.SetState(TIME_WAIT);
					SetConnectionTimeout(cs,40);

				}

				break;

			case CLOSE_WAIT:
				cout<<"in close_wait..."<<endl;
				if(IS_FIN(flags))
				{
					flags = 0;
					SET_ACK(flags);
					Packet p = CreatePacket(cs, flags);
					MinetSend(mux, p);
					SetConnectionTimeout(cs, 30);
				}
				break;

			case CLOSING:
				cout<<"in closing..."<<endl;
				if(IS_ACK(flags)&&(cs->state.SetLastAcked(ackNum)))
				{
					cs->state.SetState(TIME_WAIT);
					SetConnectionTimeout(cs,40);
				}
				else if(IS_FIN(flags))
				{
					flags = 0;
					SET_ACK(flags);
					Packet p = CreatePacket(cs, flags);
					MinetSend(mux, p);
					SetConnectionTimeout(cs,40);

				}
				break;
			case LAST_ACK:
				cout<<"in lastack..."<<endl;
				if(IS_ACK(flags)&&(cs->state.SetLastAcked(ackNum)))
				{
					ResetConnection(cs);
				}
			 	break;


			case TIME_WAIT:
				cout<<"timewait"<<endl;	
				if(IS_FIN(flags) || IS_ACK(flags))
				{
					flags = 0;
					SET_ACK(flags);
					Packet p = CreatePacket(cs, flags);
					MinetSend(mux,p);
					SetConnectionTimeout(cs, 40);
				}
				else if(IS_FIN(flags)&&(IS_ACK(flags)))
				{
					if (cs->state.SetLastAcked(ackNum))
					{
						flags = 0;
						SET_ACK(flags);
						Packet p = CreatePacket(cs, flags);
						MinetSend(mux, p);
						SetConnectionTimeout(cs, 40);
					}
				}

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
	cerr << "Received Socket Request:" << s << endl;
	unsigned char flag=0;
	Packet p;

	switch (s.type) 
	{

		case CONNECT:
		{
			cout<<"request connect..."<<endl;
			ConnectionList<TCPState>::iterator cs = connlist.FindMatching(s.connection);
			if (cs == connlist.end() || cs->state.GetState()==LISTEN)
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
				connlist.push_front(connStateMapp);
				cs = connlist.FindMatching(conn);
			}
			else if(cs->state.GetState() == CLOSED)
			{
				SetConnectionTimeout(cs);
				cs->state.SetState(SYN_SENT);
				cs->bTmrActive = true;
				cs->state.SetSendRwnd(9000);
				cs->state.SetLastRecvd(0);

			}
			else
			{}

			SET_SYN(flag);
			p = CreatePacket(cs, flag);
			MinetSend(mux, p);

			cout <<"Sent Syn";

			ReplyStatus((*cs).connection, 0, EOK);
			break;
		}
	  	case ACCEPT:
		{
			cout << "request accept"<< endl;
			if(connlist.size() == 0)
			{
				Connection conn(s.connection.src, IP_ADDRESS_ANY, s.connection.srcport, PORT_ANY, s.connection.protocol);
				TCPState tcpState(INITSEQ, LISTEN, 0);
				ConnectionToStateMapping<TCPState> connToStateMap;
				connToStateMap.connection = conn;
				connToStateMap.bTmrActive = false;
				connlist.push_back(connToStateMap);
			}

			ReplyStatus(s.connection, 0, EOK);
			break;
		}

		case WRITE:
		{
			cout<<"request write......."<<endl;
			ConnectionList<TCPState>::iterator cs = connlist.FindMatching(s.connection);
			if(cs == connlist.end())
			{
				cout <<"No such connection exist"<<endl;

			}
			else
			{
				int size = s.data.GetSize(); 
				cs->state.SendBuffer.AddBack(s.data.ExtractFront(size));
				ReplyStatus(s.connection, size, EOK);
				SendData(cs);
			}


			break;
		}
		case FORWARD:
			ReplyStatus(s.connection, 0, 0);
			break;
	  	case CLOSE:
		{
			cout<<"request close..."<<endl;
			ConnectionList<TCPState>::iterator cs = connlist.FindMatching(s.connection);
			if(cs == connlist.end())
			{
				ReplyStatus(s.connection, 0 , ENOMATCH);

			}
			else
			{
				SET_FIN(flag);
				SET_ACK(flag);
				p = CreatePacket(cs, flag);

				if(cs->state.GetState() == ESTABLISHED || cs->state.GetState() == SYN_RCVD)
				{
					MinetSend(mux, p);
					cs->state.SetState(FIN_WAIT1);
				}
				else if(cs->state.GetState() == CLOSE_WAIT)
				{
					MinetSend(mux, p);

					cs->state.SetState(LAST_ACK);
				}
				else
				{
					connlist.erase(cs);
				}

				cs->state.last_sent++;
			}


			break;
		}
		case STATUS:
		{
			cout << "request status"<<endl;
			ConnectionList<TCPState>::iterator cs = connlist.FindMatching(s.connection);
			if(s.bytes > 0)
				cs->state.RecvBuffer.Erase(0, s.bytes);

			break;
		}
		default:
	  	{

	  		cout <<"request default..."<<endl;
	    		SockRequestResponse repl;
	    	// repl.type=SockRequestResponse::STATUS;
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


Packet CreatePacket(ConnectionList<TCPState>::iterator &cs, unsigned char flags)
{
	Packet p;
	IPHeader iph;
	TCPHeader tcph;

	// Setting IP Header
	iph.SetProtocol(IP_PROTO_TCP);
	iph.SetSourceIP(cs->connection.src);
	iph.SetDestIP(cs->connection.dest);

	if(IS_SYN(flags))
		iph.SetTotalLength(TCP_HEADER_BASE_LENGTH + 4 + IP_HEADER_BASE_LENGTH);
	else
		iph.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);
	p.PushFrontHeader(iph);

	// Setting TCP Header

	tcph.SetSourcePort(cs->connection.srcport, p);
	tcph.SetDestPort(cs->connection.destport, p);

	if(IS_SYN(flags))
	{

		TCPOptions opts;
		opts.len = TCP_HEADER_OPTION_KIND_MSS_LEN;
		opts.data[0] = (char) TCP_HEADER_OPTION_KIND_MSS;
		opts.data[1] = (char) TCP_HEADER_OPTION_KIND_MSS_LEN;
		opts.data[2] = (char) ((TCP_MAXIMUM_SEGMENT_SIZE & 0xFF00) >> 8);
		opts.data[3] = (char) (TCP_MAXIMUM_SEGMENT_SIZE & 0x00FF);
		tcph.SetOptions(opts);
		tcph.SetSeqNum(cs->state.GetLastAcked(), p);
	}
	else
	{
		tcph.SetSeqNum(cs->state.GetLastSent()+1, p);
	}

	tcph.SetFlags(flags, p);
	if(IS_ACK(flags))
	{
		tcph.SetAckNum(cs->state.GetLastRecvd()+1, p);
	}
	tcph.SetWinSize(cs->state.GetRwnd(), p);

	if(IS_SYN(flags))
	{
		tcph.SetHeaderLen((TCP_HEADER_BASE_LENGTH + 4)/4, p);
	}
	else
	{
		tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4, p);
	}

	p.PushBackHeader(tcph);

	return p;

}



void ReplyStatus(Connection &conn, int replen, int error)
{
	SockRequestResponse s;
	s.type = STATUS;
	s.connection = conn;
	s.bytes = replen;
	s.error = error;
	MinetSend(sock, s);

}

void SendData(ConnectionList<TCPState>::iterator &cs)
{
	int size = cs->state.SendBuffer.GetSize();
	int acked = cs->state.last_acked;
	int sent = cs->state.last_sent;

	unsigned dataSize = size - (sent - acked);
	unsigned char flags = 0;
	SET_ACK(flags);

	unsigned byteSize;
	byteSize =dataSize;

	while ((dataSize > 0)&&(byteSize > 0))
	{


		unsigned int wSize = cs->state.last_sent - cs->state.last_acked;
		byteSize = (dataSize < cs->state.GetN()-wSize) ? dataSize: cs->state.GetN()-wSize;
		byteSize = (byteSize < cs->state.rwnd) ? byteSize : cs->state.rwnd;
		byteSize = (byteSize < TCP_MAXIMUM_SEGMENT_SIZE) ? byteSize : TCP_MAXIMUM_SEGMENT_SIZE;

		char tempBuffer[TCP_MAXIMUM_SEGMENT_SIZE + 1];
		cs->state.SendBuffer.GetData(tempBuffer, byteSize, wSize);
		Buffer payloadData(tempBuffer, byteSize);
		Packet p(payloadData);
		IPHeader iph;
		iph.SetProtocol(IP_PROTO_TCP);
		iph.SetSourceIP(cs->connection.src);
		iph.SetDestIP(cs->connection.dest);
		iph.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH + byteSize);
		p.PushFrontHeader(iph);

		TCPHeader tcph;
		tcph.SetSourcePort(cs->connection.srcport, p);
		tcph.SetDestPort(cs->connection.destport, p);
		tcph.SetSeqNum(cs->state.GetLastSent() + 1, p);
		tcph.SetAckNum(cs->state.GetLastRecvd() + 1, p);
		tcph.SetFlags(flags, p);
		tcph.SetWinSize(cs->state.GetRwnd(), p);
		tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4, p);

		p.PushBackHeader(tcph);
		MinetSend(mux,p);
		cs->state.last_sent = cs->state.last_sent + byteSize;
		dataSize -= byteSize;


	}


}

void TimeoutHandler(ConnectionList<TCPState>::iterator &cs)
{
	unsigned char flags = 0;
	Packet p;
	switch(cs->state.GetState())
	{
		case SYN_RCVD:
			{
			SET_SYN(flags);
			SET_ACK(flags);
			p = CreatePacket(cs, flags);
			MinetSend(mux,p);
			SetConnectionTimeout(cs);
			break;
			}
		case ESTABLISHED:
			//Go Back-N
			if(cs->state.SendBuffer.GetSize())
			{
				unsigned int ackNum = cs->state.GetLastAcked();
				cs->state.SetLastSent(ackNum);
				SendData(cs);
			}
			else
			{
				SET_ACK(flags);
				p = CreatePacket(cs, flags);
				MinetSend(mux,p);

			}
			SetConnectionTimeout(cs);
			break;

		case LISTEN:
			break;

		case CLOSE_WAIT:
			ResetConnection(cs);
			break;

		case SYN_SENT:
		{
			if(cs->state.tmrTries == 0)
			{
				SockRequestResponse reply(WRITE, cs->connection, cs->state.RecvBuffer, 0, (ECONN_FAILED));
				MinetSend(sock, reply);
 				ResetConnection(cs);
			}
			cs->state.tmrTries--;
			
			SET_SYN(flags);
			p = CreatePacket(cs, flags);
			MinetSend(mux,p);

			SetConnectionTimeout(cs);

			break;
		}
		case LAST_ACK:
		{
			SET_FIN(flags);
			SET_ACK(flags);
			p = CreatePacket(cs, flags);
			MinetSend(mux,p);
			
			SetConnectionTimeout(cs);

			break;
		}
		case FIN_WAIT1:
			SET_FIN(flags);
			SET_ACK(flags);
			p = CreatePacket(cs, flags);
			MinetSend(mux,p);
			SetConnectionTimeout(cs);
			break;

		case CLOSING:
			SET_ACK(flags);
			p = CreatePacket(cs, flags);
			MinetSend(mux,p);
			SetConnectionTimeout(cs);

			break;

		case TIME_WAIT:
			ResetConnection(cs);
			break;

		default:
			SetConnectionTimeout(cs);
			break;

	}

}
void SetConnectionTimeout(ConnectionList<TCPState>::iterator &cs, int inc)
{
	cs->timeout.SetToCurrentTime();
	cs->timeout.tv_sec+=inc;
}

void ResetConnection(ConnectionList<TCPState>::iterator &cs)
{
	cs->state.last_acked = INITSEQ - 1;
	cs->state.last_sent = INITSEQ - 1;
	cs->state.stateOfcnx = CLOSED;
	cs->bTmrActive = false;
}


/*******************************************************************/
