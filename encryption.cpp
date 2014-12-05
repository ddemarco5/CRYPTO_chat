#include <string>
#include <sstream>
#include <iostream>
#include <utility>           // For data size and type in the stacks (Pair is used)
#include <map>
#include <fstream>
#include <time.h>


//#include "NTL/ZZ.h"


//For AES
#include <iomanip>

#include "modes.h"
#include "aes.h"
#include "filters.h"
#include "encryption.h"
#include "osrng.h"

using namespace std;
using namespace NTL;
using namespace CryptoPP;

//AES Keylength
int AES_KEYLENGTH;

//GLOBAL KEYS. BE CAREFUL! EVERYTHING BUT N AND e ARE PRIVATE
ZZ p,q,phi,e,N,d;
//OUR AES KEYS
//SecByteBlock key(0x00, AES_KEYLENGTH);
SecByteBlock key;
byte iv[AES::BLOCKSIZE];
//THEIR AES KEYS
//SecByteBlock their_key(0x00, AES_KEYLENGTH);
SecByteBlock their_key;
byte their_iv[AES::BLOCKSIZE];

//These will return the ZZ values of the keys to the buffer passed into them
//string getN(){ return to_string(conv<long>(N)); }
//string getE(){ return to_string(conv<long>(e)); }
string getN(){
    stringstream ss;
    ss << N;
    string ret;
    ss >> ret;
    return ret;
}
string getE(){
    stringstream ss;
    ss << e;
    string ret;
    ss >> ret;
    return ret;
}

void rsa_genkeys(long bitlength){
    //generate the p and q primes
    ZZ seed((long)time(NULL));
    SetSeed(seed);
    RandomPrime(p,bitlength);
    NextPrime(q, p+1);
    e = 3;
    phi = (q-1) * (p-1);
    N = q*p;
    while(GCD(phi, e) != 1){
        e++;
        cout << "Increasing e to " << e << ".\n";
    }
    cout << "\n";

    ZZ z(conv<ZZ>(e));

    d = InvMod(e, phi);
    cout << "p = " << p << "\n";
    cout << "q = " << q << "\n";
    cout << "e = " << e << "\n";
    cout << "N = " << N << "\n";
    cout << "phi = " << phi << "\n";
    cout << "d = " << d << "\n";
}

pair<unsigned int*, int> rsa_decrypt(pair<unsigned int*, int> message){
    unsigned int * encrypted = message.first;
    int msgsize = message.second;
    //the string we'll fill with the decrypted info.
    unsigned int * decrypted = new unsigned int[msgsize];
    for(int i=0; i<msgsize; i++) {
        //cout << conv<ZZ>(encrypted[i])%N << "^" << d << " (mod " << N << ")\n";
        decrypted[i] = conv<unsigned int>(PowerMod(conv<ZZ>(encrypted[i])%N,d,N));
        //cout << "decresult: " << (unsigned int)decrypted[i] << endl;
    }
    //cout << "dec: " << decrypted << endl;
    return pair<unsigned int*, int>(decrypted, msgsize);
}

//this is the function of the assignment to encrypt it again.
pair<unsigned int*, int> rsa_encrypt(pair<unsigned int*, int> message, ZZ N, ZZ e){

    unsigned int * to_encrypt = message.first;
    int msgsize = message.second;
    //cout << "TOENCRYPT: " << to_encrypt[0] << endl;

    //unsigned char encme[to_encrypt.length()];
    //memcpy(encme, to_encrypt, to_encrypt.length());

    unsigned int * encrypted = new unsigned int[msgsize];
    for(int i = 0; i < msgsize; i++){
        //cout << conv<ZZ>(to_encrypt[i]) << "^" << e << " (mod " << N << ")" << endl;
        ZZ tmp(PowerMod(conv<ZZ>(to_encrypt[i])%N, e, N)); ZZ biggest(2147483647);
        if(tmp > biggest){ cout << "DATA LOSS DETECTED! RSA KEY TOO LARGE. ABORTING.\n", exit(1);}
        encrypted[i] = conv<unsigned int>(PowerMod(conv<ZZ>(to_encrypt[i])%N, e, N));
        //cout << "encresult: " << (unsigned int)encrypted[i] << endl;
    }

    return pair<unsigned int*, int>(encrypted, msgsize);
}


pair<unsigned int*, int> aes_encrypt(pair<unsigned int*, int> message){

    unsigned int * encrypted = new unsigned int[message.second];
    for(int i=0; i<message.second; i++){
        encrypted[i]=message.first[i];
    }

    CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
    cfbEncryption.ProcessData((byte*)encrypted, (byte*)encrypted, message.second*sizeof(int));

    //string retstring(plainText);
    return pair<unsigned int*, int>(encrypted, message.second);
}


pair<unsigned int*, int> aes_decrypt(pair<unsigned int*, int> cipher){

    unsigned int * message = new unsigned int[cipher.second];
    for(int i=0; i<cipher.second; i++){
        message[i]=cipher.first[i];
    }


    CFB_Mode<AES>::Decryption cfbDecryption(their_key, their_key.size(), their_iv);
    cfbDecryption.ProcessData((byte*)message, (byte*)message, cipher.second*sizeof(int));

    //string retstring(plainText);
    return pair<unsigned int*, int>(message, cipher.second);
}

void aes_genkeys(int length){
    AES_KEYLENGTH = length;
    cout << "Generating random AES key and iv\n";
    AutoSeededRandomPool rnd;

    // Generate a random key
    key.New(AES_KEYLENGTH);
    their_key.New(AES_KEYLENGTH);
    rnd.GenerateBlock( key, key.size() );
    their_key = key;

    // Generate a random IV
    //byte iv[AES::BLOCKSIZE];
    rnd.GenerateBlock(iv, AES::BLOCKSIZE);
    memcpy(their_iv, iv, AES::BLOCKSIZE);

}

void aes_setkeys(pair<unsigned int*, int> keypair, pair<unsigned int*, int> ivpair){

    SecByteBlock newkey(0x00, keypair.second);
    for(int i=0; i<keypair.second; i++){
        newkey.data()[i]=keypair.first[i];
    }
    their_key = newkey;

    for(int i=0; i<ivpair.second; i++){
        their_iv[i]=ivpair.first[i];
    }
}

pair<unsigned int*, int> getKey(){
    unsigned int * tmp = new unsigned int[key.size()];
    for(int i=0; i<key.size(); i++){
        tmp[i]=key.data()[i];
    }
    //memcpy(tmp, key.data(), key.size());
    return pair<unsigned int*, int>(tmp, key.size());
}

pair<unsigned int*, int> getIV(){
    unsigned int * tmp = new unsigned int[key.size()];
    for(int i=0; i<key.size(); i++){
        tmp[i]=iv[i];
    }
    //memcpy(tmp, iv, key.size());
    return pair<unsigned int*, int>(tmp, key.size());
}

/*int aes() {

    aes_genkeys();

    //cout << "Key= " << getKey() << endl;
    //cout << "IV= " << getIV() << endl;

    aes_setkeys(getKey(), getIV());

    string message = "Will this work for a longer message?";

    cout << message << endl;

    pair<unsigned int*, int> encrypted = aes_encrypt(message);

    //cout << encrypted << endl;

    pair<unsigned int*, int> decrypted = aes_decrypt(encrypted);

    //cout << decrypted << endl;

    return 0;
}*/
