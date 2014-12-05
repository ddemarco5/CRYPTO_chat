#include <iostream>
#include <string>
#include <fstream>
#include "NTL/ZZ.h"

using namespace std;
using namespace NTL;

ZZ p(INIT_VAL, "14674584631911578835797418783385886014282097732848477104726443478638332485502347247543655947605449957396117669498208741164913923801974405155475348168889579");

ZZ q(INIT_VAL, "7337292315955789417898709391692943007141048866424238552363221739319166242751173623771827973802724978698058834749104370582456961900987202577737674084444789");

ZZ g(INIT_VAL, "4982841904814869672085039202622244483970253128052169343896265812258636257432659143378521974063258583724954123861596060493488326314054712412448027305717254");

ZZ g_sqd_modp(INIT_VAL, "4512332801204145837647149816192207114690569993766496571525710001167915985214512678196010903604329224278200626019048368054570643789087312844115891682754848");

ZZ g_qd_modp(INIT_VAL, "14674584631911578835797418783385886014282097732848477104726443478638332485502347247543655947605449957396117669498208741164913923801974405155475348168889578");

ZZ a(INIT_VAL, "8385809758725413340345527512446047025233684014661139532797265337676097725723596969305230319151167266083830582325785380987669989704814122581554084050167540");

ZZ b(INIT_VAL, "9111900488916451317627454621907193345267024264535396935398533304218215650993309410206906051098315918657553576294918817950897114918977375048148520131923664");

int main(){
    ifstream cipherfile("cipher.txt");
    ofstream decfile("decrypted.txt");
    string c_s, hm_s;
    ZZ c, hm, Z, m;
    while(cipherfile){
        cipherfile >> hm_s >> c_s;
        //convert read values into ZZ
        c = conv<ZZ>(c_s.c_str());
        hm = conv<ZZ>(hm_s.c_str());
        //cout << c << ", " << hm << "\n";
        decfile << (char)conv<int>(MulMod(c ,InvMod(PowerMod(hm, a, p), p), p));
    }
cipherfile.close();
decfile.close();
}
