#include "PracticalSocket.h" // For UDPSocket and SocketException
#include <queue>             // For our received data
#include <cstdlib>           // For atoi()
#include <cstring>
#include <thread>
#include <chrono>
#include <mutex>

#include "encryption.h" //homemade encryption function (and aes)

using namespace std;


const int BUFMAX = 65507;     // Longest string to echo
unsigned short listenPort;
unsigned short sendPort;

int rsa_keylength;
int aes_keylength;
string dest_ip;

//The socket we will be sending on.
UDPSocket sendSock;

//Our public stack.
queue<pair<unsigned int *, int>> messageQueue;
mutex mqmutex;

queue<pair<unsigned int *, int>> sendQueue;
mutex sqmutex;

void listenThread();
void sendThread();
void decryptThread();
void talkThread();
void sendPacket(pair<unsigned int*, int> message, string sendAddress, unsigned short sendPort);

void printMsg(pair<unsigned int *, int> message){
    for(int i=0; i<message.second; i++){
        cout << "0x" << hex << message.first[i];
        cout << " ";
    }
}

pair<unsigned int *, int> strtoPair(string msg){
    unsigned int * tosend = new unsigned int[msg.length()];
    //memcpy(tosend, msg.c_str(), msg.length());
    for(int i=0; i<msg.length(); i++){
        tosend[i]=msg[i];
    }
    return pair<unsigned int*, int>(tosend, msg.length());
}

void queueMsg(pair<unsigned int *, int> queuepair){
    sqmutex.lock();
    //cout << "Requesting '" << msg << "'\n";
    sendQueue.push(queuepair);
    sqmutex.unlock();
}

pair<unsigned int*, int> getMsg(){
    //if there is no message, wait for one.
    while(messageQueue.empty()){
		#ifdef WIN32
		_sleep(1);
		#else
		this_thread::sleep_for(chrono::milliseconds(1));
		#endif
	}
    mqmutex.lock();
    pair<unsigned int*, int> tmp = messageQueue.front();
    //string tmp = messageQueue.front();
    //Frees the int array. comment out if having problems. (In know I know...)
    //delete[] messageQueue.front().first;
    messageQueue.pop();
    mqmutex.unlock();
    return tmp;
}

bool msgCompare(pair<unsigned int*, int> msg, string str){
    for(int i=0; i<str.length(); i++){
        if(msg.first[i]!=(unsigned int)str[i]) return false;
    }
    return true;
}

string msgtoString(pair<unsigned int*, int> msg){
    char tmp[msg.second+1];
    for(int i=0; i<msg.second; i++){
        tmp[i] = msg.first[i];
    }
    //memcpy(tmp, msg.first, msg.second);
    tmp[msg.second] = '\0';
    return string(tmp);
}

int main() {
    /*if (argc != 3) {                  // Test for correct number of parameters
        cerr << "Usage: " << argv[0] << " <Receive Port> <Destination Port>" << endl;
        exit(1);
    }*/
    cout << "\nWelcome to RSA key exchange + AES encrypted chat!\n\n\n";

    cout << "RSA Keylength?(14-15 max, as this is a program that preserves data size): ";
    cin >> rsa_keylength;

    cout << "AES Keylength?(16, 24, or 32): ";
    cin >> aes_keylength;
    if(!(aes_keylength==16 || aes_keylength==24 || aes_keylength==32)){
        cout << "Invalid keylength.\n";
        exit(0);
    }

    cout << "Destination IP: ";
    cin >> dest_ip;

    cout << "Sending port: ";
    cin >> sendPort;

    cout << "Receiving port: ";
    cin >> listenPort;

    // C++ trick to not break output between threads.
    ios_base::sync_with_stdio(false);
    cin.tie(nullptr);
    cerr.tie(nullptr);
    //end trick

    //cout << "QUEUESIZES(M,S): " << messageQueue.size() << "," << sendQueue.size() << "\n";

    rsa_genkeys(rsa_keylength);

    //listenPort = atoi(argv[1]);     // First arg:  local port
    //sendPort = atoi(argv[2]);     // Second arg: destination port

    //The partner's public keys.
    ZZ N, e;

    //START THREADING
    thread send(sendThread);
    thread listen(listenThread);
    cout << "Listening... " << listenPort << endl;

    //INITIALIZATION.
    //initial message sending.
    queueMsg(strtoPair("Hello."));
    while(messageQueue.empty()){
	#ifdef WIN32
	_sleep(1);
	#else
	this_thread::sleep_for(chrono::milliseconds(1));
	#endif
    }
    queueMsg(strtoPair("N"));
    queueMsg(strtoPair(getN()));
    queueMsg(strtoPair("e"));
    queueMsg(strtoPair(getE()));

    //Wait for all the initial packets to come.
    for(int i=0; i<4; i=messageQueue.size()){
	#ifdef WIN32
	_sleep(1);
	#else
	this_thread::sleep_for(chrono::milliseconds(1));
	#endif
    }
    cout << "Packets Received.\n";

    //Do something about this fugly thing below Dom
    //for(;;){
    while(!messageQueue.empty()){
        //Request N.
        pair<unsigned int*, int> msg = getMsg();

        //grab the initial message from the queue.
        //send N if other needs it.
        if(msgCompare(msg, "need N.")){
            queueMsg(strtoPair("N"));
            queueMsg(strtoPair(getN()));
        }
        //send e if other needs it.
        if(msgCompare(msg, "need e.")){
            queueMsg(strtoPair("e"));
            queueMsg(strtoPair(getE()));
        }
        //If N is found and we need it, set it.
        if(msgCompare(msg, "N") && N == 0){
            cout << "Found trigger N" << endl;
            //Get the next message, which will be the value.
            N = conv<ZZ>(msgtoString(getMsg()).c_str());
            cout << "N set to " << N << endl;
        }
        //If e is found and we need it, set it.
        if(msgCompare(msg, "e") && e == 0){
            cout << "Found trigger e" << endl;
            //Get the next message, which will be the value.
            e = conv<ZZ>(msgtoString(getMsg()).c_str());
            cout << "e set to " << e << endl;
        }

        //If no other cases
        //else cout << "Non-Triggered message " << msgtoString(msg) << endl;
    }
    //these little bastards will only execute if the N and e packets weren't transmitted correctly
    if(N==0 && messageQueue.empty()){
        queueMsg(strtoPair("need N."));
    }
    if(e==0 && messageQueue.empty()){
        queueMsg(strtoPair("need e."));
    }

    cout << "N: " << N << endl;
    cout << "e: " << e << endl;

    //}
    //END INIT.

    //Generate AES key and iv.
    aes_genkeys(aes_keylength);

    cout << "AES key: " << msgtoString(getKey())<< endl;
    cout << "AES iv: " << msgtoString(getIV())<< endl;

    //Send our key.
    pair<unsigned int*, int> encrypted_key = rsa_encrypt(getKey(), N, e);
    queueMsg(encrypted_key);
    //cout << "enc key: "; printMsg(encrypted_key); cout << endl;
    pair<unsigned int*, int> encrypted_iv = rsa_encrypt(getIV(), N, e);
    queueMsg(encrypted_iv);
    //cout << "enc iv: "; printMsg(encrypted_iv); cout << endl;

    //Wait for keys.
    pair<unsigned int*, int> key = rsa_decrypt(getMsg());
    pair<unsigned int*, int> iv = rsa_decrypt(getMsg());

    cout << "Received AES key: " << msgtoString(key) << " of size " << key.second << endl;
    cout << "Received AES iv: " << msgtoString(iv) << " of size " << iv.second<< endl;

    //AES testing stuff
    aes_setkeys(key, iv);

    /*pair<unsigned int*, int> encrypted = aes_encrypt(strtoPair("Will this work?"));

    cout << "encrypted: " << msgtoString(encrypted) << endl;

    queueMsg(encrypted);

    pair<unsigned int*, int> decrypted = aes_decrypt(getMsg());

    cout << "decrypted: " << msgtoString(decrypted) << endl;
    */
    //Start persistent decrypting thread.
    thread decrypt(decryptThread);
    thread talk(talkThread);

    /*for(;;){
        string message;
        cin >> message;
        queueMsg(aes_encrypt(strtoPair(message)));
    }*/
    //queueMsg(aes_encrypt(strtoPair("MARCO!")));


    //exit(0);
    talk.join();
    decrypt.join(); //not needed when one has joined talk.
    //send.join();
    //listen.join();


    return 0;
}

void talkThread(){
    cout << "\n\nReady to send.\n";
    cout << flush;
    char message[BUFMAX];
    for(;;){
        cin.getline(message, BUFMAX);
        queueMsg(aes_encrypt(strtoPair(message)));
    }
}

void decryptThread(){
    cout << "Starting decryption listener.\n";
    for(;;){
        cout << "msg: " << msgtoString(aes_decrypt(getMsg())) << endl;
    }
}

void sendThread(){
    //char sendBuffer[BUFMAX];         // Buffer for echo string
    cout << "Starting send thread\n";

    for(;;){
        //This is the refresh (sending) rate. Raise it to take it easy on the processor.
        this_thread::sleep_for(chrono::milliseconds(1));

        sqmutex.lock();
        if(!sendQueue.empty()){
            //cout << "TRIGGERED!";
            //int msglength = sendQueue.front().length() + 1;
            //char tmp[msglength];
            //strcpy(tmp, sendQueue.front().c_str());
            pair<unsigned int*, int> tosend = sendQueue.front();
            sendPacket(tosend, dest_ip, sendPort);
            sendQueue.pop();
        }
        sqmutex.unlock();
    }
}


void listenThread(){
    cout << "Starting listening thread\n";
    UDPSocket listenSock(listenPort);

    unsigned int recieveBuffer[BUFMAX];         // Buffer for echo string
    int recvMsgSize;                  // Size of received message
    string sourceAddress;             // Address of datagram source
    unsigned short sourcePort;        // Port of datagram source
    try {
        for (;;) {  // Run forever
            // Block until receive message from a clients
            recvMsgSize = listenSock.recvFrom(recieveBuffer, BUFMAX, sourceAddress, sourcePort);
            cout << "Received packet from " << sourceAddress << ":" << sourcePort;

            unsigned int * recieved = new unsigned int[recvMsgSize*sizeof(int)];
            memcpy(recieved, recieveBuffer, recvMsgSize*sizeof(int));
            //msgsize = recvMsgSize;
            pair<unsigned int*, int> tmp(recieved, recvMsgSize/sizeof(int));
            cout << " -- " << msgtoString(tmp) << endl;
            mqmutex.lock();
            //cout << "RECIEVEDSTRING: " << receiveString << endl;
            messageQueue.push(tmp);
            mqmutex.unlock();
        }
    } catch (SocketException &e) {
        cerr << e.what() << endl;
        exit(1);
    }
}

void sendPacket(pair<unsigned int*, int> msgpair, string sendAddress, unsigned short sendPort){
    unsigned int * message = msgpair.first;
    int msglength = msgpair.second;
    cout << "Sending packet: " << msgtoString(msgpair)<< endl;
    try {
        sendSock.sendTo(message, msglength*sizeof(int), sendAddress, sendPort);
    }catch (SocketException &e) {
        cerr << e.what() << endl;
        exit(1);
    }
}

