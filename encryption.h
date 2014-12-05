#include <string>
#include <iostream>
#include <map>
#include <fstream>
#include <time.h>


#include "NTL/ZZ.h"

using namespace std;
using namespace NTL;

string getN();
string getE();
pair<unsigned int*, int> rsa_decrypt(pair<unsigned int*, int> message);
pair<unsigned int*, int> rsa_encrypt(pair<unsigned int*, int> message, ZZ N, ZZ e);
void rsa_genkeys(long bitlength);

pair<unsigned int*, int> getIV();
pair<unsigned int*, int> getKey();
void aes_genkeys(int length);
void aes_setkeys(pair<unsigned int*, int> keypair, pair<unsigned int*, int> ivpair);
pair<unsigned int*, int> aes_decrypt(pair<unsigned int*, int> cipher);
pair<unsigned int*, int> aes_encrypt(pair<unsigned int*, int> message);
