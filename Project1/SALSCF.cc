#include <iostream>
#include <fstream>
#include <string>
#include <openssl/des.h>
#include <openssl/rand.h>
#include <vector>
#include <sstream>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdexcept>


using namespace std;
int DEBUG = 1;
string W[] = {"LogleInitializationType","MessageType","NormalCloseMessage","ResponseMessageType","AbnormalCloseType"};



ofstream file;
int lock = 0;
int id;
time_t d;
time_t dplus;
string idlog;
string A0;
string LastA;
int padding = RSA_PKCS1_PADDING;
int glb_k0_len;
const char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
/*
unsigned char* strHex(string data){
  unsigned char ret[data.length()/2];
  return ret;
}
*/


std::string hexStr(unsigned char *data, int len)
{
  std::string s(len * 2, ' ');
  for (int i = 0; i < len; ++i) {
    s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data[i] & 0x0F];
  }
  return s;
}

std::string string_to_hex(const std::string& input)
{
  static const char* const lut = "0123456789ABCDEF";
  size_t len = input.length();

  std::string output;
  output.reserve(2 * len);
  for (size_t i = 0; i < len; ++i)
    {
      const unsigned char c = input[i];
      output.push_back(lut[c >> 4]);
      output.push_back(lut[c & 15]);
    }
  return output;
}


std::string hex_to_string(const std::string& input)
{
  static const char* const lut = "0123456789ABCDEF";
  size_t len = input.length();
  if (len & 1) throw std::invalid_argument("odd length");

  std::string output;
  output.reserve(len / 2);
  for (size_t i = 0; i < len; i += 2)
    {
      char a = input[i];
      const char* p = std::lower_bound(lut, lut + 16, a);
      if (*p != a) throw std::invalid_argument("not a hex digit");

      char b = input[i + 1];
      const char* q = std::lower_bound(lut, lut + 16, b);
      if (*q != b) throw std::invalid_argument("not a hex digit");

      output.push_back(((p - lut) << 4) | (q - lut));
    }
  return output;
}

RSA * createRSA(unsigned char * key,int publica)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(publica)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
 
    return rsa;
}
 
unsigned char* public_encrypt(unsigned char * data,int data_len,unsigned char * key)
{
  unsigned char encrypted[4098] = {};  
  RSA * rsa = createRSA(key,1);  
  int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
  unsigned char* ret = encrypted;

  if(result == -1){
    cout<<"public_encrypt fails!"<<endl;
    exit(-1);
  }

  return ret;
}


unsigned char* private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key)
{
  unsigned char decrypted[4098];
  RSA * rsa = createRSA(key,0);
  int  result = RSA_private_decrypt( data_len,enc_data,decrypted,rsa,padding );

  if(result == -1){
    cout<<"private_decrypt fails!"<<endl;
    exit(-1);
  }
  unsigned char* ret = decrypted;
  return ret;
}


unsigned char* private_encrypt(unsigned char * data,int data_len,unsigned char * key)
{
  unsigned char encrypted[4098];
  
  RSA * rsa = createRSA(key,0);
  //data = (unsigned char*)"abcde";

  int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
  
  if(result == -1){
    cout<<"private_encrypt fails!"<<endl;
    exit(-1);
   }

  unsigned char* ret = encrypted;
  return ret;
}


unsigned char* public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key)
{
  unsigned char decrypted[4098];
  RSA * rsa = createRSA(key,1);
  int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
  if(result == -1){
    cout<<"public_decrypt fails!"<<endl;
    exit(-1);
  }

    
  unsigned char* ret = decrypted;
  return ret;
  
}


vector<string> split(string orignal, char target){
  vector<string> ret;
  stringstream ss(orignal);
  string token;
  
  while ( getline(ss, token, target) ){
    ret.push_back(token);
    if(DEBUG)
      cout<<"Split out: "<<token<<endl;
  }
  return ret;
}

string Hash(const char* string){
  
  char outputBuffer[64];
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, string, strlen(string));
  SHA256_Final(hash, &sha256);
  int i = 0;
  for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
      sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
  outputBuffer[64] = 0;
  
  std::string ret(outputBuffer);
  return ret;
}

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, 
             EVP_CIPHER_CTX *d_ctx)
{
  int i, nrounds = 8;
  unsigned char key[32], iv[32];
  
  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
}

char *
Encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = (unsigned char*)malloc(c_len);

  /* allows reusing of 'e' for multiple encryption cycles */
  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
   *len is the size of plaintext in bytes */
  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

  /* update ciphertext with the final remaining bytes */
  EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  return (char*)ciphertext;

}

char *
Decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = (unsigned char*)malloc(p_len);
  
  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return (char*)plaintext;
}

void send_M0_to_t(string M0){
  std::stringstream ss(M0);
  int count = 0;
  string piece;
  string temp_enc;
  string hex_EK0;
  while(std::getline(ss, piece, ',')) {
    if(count == 2){
      temp_enc = piece;
    }else if(count == 3){
      hex_EK0 = piece;
    }
    cout<<count<<":\n"<<piece<<endl;
    count++;
  }

  if(DEBUG){
    cout<<"PKEK0 is:"<<endl<<temp_enc<<endl;
  }
  ifstream tpri("SALSCFt.pri");
  string t_pri((std::istreambuf_iterator<char>(tpri)),
	       std::istreambuf_iterator<char>());
  cout<<"Private key for t is:\n"<<t_pri<<endl;

  temp_enc = hex_to_string(temp_enc);
  unsigned char* enc = (unsigned char*)temp_enc.c_str();
  unsigned char* dec = private_decrypt((unsigned char*)enc,128, (unsigned char*)t_pri.c_str());
  if(DEBUG){
    string debug = hexStr(dec,64);
    cout<<"Decrypted PKE_K0 is:\n"<<debug<<endl;
  }
}




void write( int message_size, string w, string encipher,string y, string z){
  file<<message_size<<"|"<<w<<"|"<<string_to_hex(encipher)<<"|"<<string_to_hex(y)<<"|"<<string_to_hex(z)<<endl;
}



void createlog(string filename){
  if(DEBUG)
    cout<<"Creating file: "<<filename<<endl;


  if( lock ){
    cout<<"You already open a log!"<<endl;
    return;
  }
  ifstream ifile(filename.c_str());
  if (ifile) {
    cout<<"file already exist, please choose another file!"<<endl;
    return;
    // The file exists, and is open for input
  }



 
  if( idlog.empty() ){
    //file.open( filename.c_str(), ios::out | ios::app | ios::trunc );
    file.open(filename.c_str());
    
  }
  else{
    cout<<"You already open a log!"<<endl;
    lock = 0;
    return;
  }
  
  // Initialize
  id = 0;
  time(&d);


  ifstream myfile ("SALSCF.symm");
  if (myfile.is_open())
    {
      string a0((std::istreambuf_iterator<char>(myfile)),
		     std::istreambuf_iterator<char>());
      A0 = a0;
      myfile.close();
    }

  if(DEBUG)
    cout<<"A0: "<<string_to_hex(A0)<<endl;

  unsigned int salt[] = {12345, 54321};
  string key_data = Hash( (W[0]+A0).c_str() );
  int key_data_len = key_data.length();
  
  EVP_CIPHER_CTX en, de;

 
  if (aes_init( (unsigned char*)key_data.c_str(), key_data_len, (unsigned char *)&salt, &en, &de)) {
    printf("Couldn't initialize AES cipher\n");
    return;
  }

  //##################################
  // Startup
  struct tm * timeinfo;
  timeinfo = localtime (&d);
  timeinfo->tm_min += 100;
  dplus = mktime(timeinfo);
  idlog = filename;
  LastA = A0;
  
  int k0_len = key_data_len;
  /*
  unsigned char k0[k0_len];
  memset(k0, 0, sizeof(k0));
  if (!RAND_bytes(k0, k0_len))
    {
      exit(-1);
    }
  */
  unsigned char* k0 = (unsigned char*)key_data.c_str();

  unsigned char iv[AES_BLOCK_SIZE];
  if (!RAND_bytes(iv, AES_BLOCK_SIZE))
    {
      exit(-1);
    }

  AES_KEY enc_key, dec_key;
  unsigned char enc_out[AES_BLOCK_SIZE];
  unsigned char dec_out[AES_BLOCK_SIZE];
  AES_set_encrypt_key(k0, k0_len, &enc_key);


  // Deal with certificate
  ifstream t("SALSCFu.pem");
  string cer((std::istreambuf_iterator<char>(t)),
                 std::istreambuf_iterator<char>());

  // Conver pem to X509
  const unsigned char *data = (const unsigned char*)cer.c_str();
  BIO *bio;
  X509 *certificate;
  bio = BIO_new(BIO_s_mem());
  BIO_puts(bio, (const char*)data);
  certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  // Conver ends here
  
  string D0( ctime(&d) );
  string temp( ctime(&dplus) );
  D0 = D0 + temp;
  D0 += idlog;   
  string X0("0,");
  X0 += idlog;
  X0 += ",";
  X0 += string_to_hex(cer);
  X0 += ",";
  X0 += string_to_hex(A0);
  
  //# Use t's public key to encrypt K0
  ifstream tpub("SALSCFt.pub");
  string t_pub((std::istreambuf_iterator<char>(tpub)),
	     std::istreambuf_iterator<char>());
  
  if(DEBUG){
    cout<<"Public key for t is:\n"<<t_pub<<endl;
    cout<<"k0:"<<endl<<hexStr(k0,k0_len)<<endl;
  }
  unsigned char* enc = public_encrypt(k0,k0_len, (unsigned char*)t_pub.c_str());
  string PKEK0 = hexStr(enc, 128);
  
  if(DEBUG){
    cout<<"PKE_K0:"<<endl<<PKEK0<<endl;
    ifstream tpri("SALSCFt.pri");
    string t_pri((std::istreambuf_iterator<char>(tpri)),
		 std::istreambuf_iterator<char>());
  

    cout<<"Private key for t is:\n"<<t_pri<<endl;
    unsigned char* dec = private_decrypt(enc,128, (unsigned char*)t_pri.c_str());

    string debug = hexStr(dec,k0_len);

    cout<<"Decrypted PKE_K0 is:\n"<<debug<<endl;
  }

  //# Sign X0
  ifstream upri("SALSCFu.pri");
  string u_pri((std::istreambuf_iterator<char>(upri)),
	       std::istreambuf_iterator<char>());
  if(DEBUG){
    cout<<"X0: "<<endl<<X0<<endl;
    cout<<"private key for u is:"<<endl<<u_pri<<endl;
  }


  unsigned char X0_hash[20];
  SHA1((const unsigned char*)X0.c_str(), X0.length(), X0_hash);
  unsigned char* sig = private_encrypt(X0_hash, 20, (unsigned char*)u_pri.c_str());
  if(DEBUG){
    cout<<"X0 Hash is:"<<endl<<hexStr(X0_hash, 20)<<endl;
    ifstream upub("SALSCFu.pub");
    string u_pub((std::istreambuf_iterator<char>(upub)),
		 std::istreambuf_iterator<char>());
    cout<<"public key for u is:"<<endl<<u_pub<<endl;
    unsigned char* org = public_decrypt(sig, 128, (unsigned char*)u_pub.c_str());
    cout<<"Orignial X0 Hash is:"<<endl<<hexStr(org, 20)<<endl;
  }

  string temp_EK0 = X0+","+hexStr(X0_hash,20);
  if(DEBUG){
    cout<<"Message in EK0 is:"<<endl<<temp_EK0<<endl;
  }
  int temp_EK0_len = temp_EK0.length();
  unsigned char* EK0 = (unsigned char*)Encrypt(&en, (unsigned char*)temp_EK0.c_str(), &temp_EK0_len);

  int EK0_len = temp_EK0_len;
  if(DEBUG){
    string dec_EK0 = string( Decrypt( &de, EK0, &temp_EK0_len) );
    cout<<"---------------\nDecrypt data: \n"<<dec_EK0<<endl;
  }

  string M0("0");
  M0 += ","+idlog +","+PKEK0 + ","+hexStr(EK0, EK0_len);
  D0 += M0;

  send_M0_to_t(M0);
  exit(-1);
  // Startup ends here
  //##################################
 


  //################################################

  int plaintext_len = D0.length()+1;
  if(DEBUG)
    cout<<"Key for D0 is: "<<key_data<<", with size: "<<key_data_len<<endl;
     
  unsigned char* ciphertext = (unsigned char*)Encrypt(&en, (unsigned char*)D0.c_str(), &plaintext_len);
  string encipher( (const char*)ciphertext);

  //###############################################
  if(DEBUG){
    cout<<"---------------\nEncrypt data: \n"<<string_to_hex(encipher)<<endl;
    string decipher = string( Decrypt( &de, ciphertext, &plaintext_len) );
    cout<<"---------------\nDecrypt data: \n"<<decipher<<endl;
  }
  //###############################################
  
  string y = Hash( (encipher+W[0]).c_str() );
  if(DEBUG)
    cout<<"Y: "<<y<<", with size: "<<y.size()<<endl;
  
  char tempZ[21];
  
  unsigned int zlength = 20;
  HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);
  HMAC_Init_ex(&ctx,A0.c_str(),20,EVP_sha256(),NULL);
  HMAC_Update(&ctx,(const unsigned char *)y.c_str(),20);
  HMAC_Final(&ctx,(unsigned char *)tempZ,&zlength);

  tempZ[20] = '\0';
  string z(tempZ);


  if(DEBUG)
    cout<<"Z: "<<string_to_hex(z)<<", with size: "<<z.size()<<endl;


  if(file.is_open()){
    //file<<W[0]<<"|"<<encipher<<endl;
    write(D0.size(), W[0], encipher,y,z);
    id++;
    
  }else{
    cout<<"File open failed\n";
    exit(0);
  }

  lock = 1;

}


void add(string message){
  if(DEBUG)
    cout<<"Adding message: "<<message<<endl;

  string A = Hash( LastA.c_str() );
  string Df = message;

  



  
  //################################################
  unsigned int salt[] = {12345, 54321};
  string key_data = Hash( (W[1]+A).c_str() );
  int key_data_len = key_data.length();
  int plaintext_len = Df.length()+1;
  EVP_CIPHER_CTX en, de;

  if(DEBUG)
    cout<<"Key for Df is: "<<key_data<<", with size: "<<key_data_len<<endl;
    
  if (aes_init( (unsigned char*)key_data.c_str(), key_data_len, (unsigned char *)&salt, &en, &de)) {
    printf("Couldn't initialize AES cipher\n");
    return;
  }

  
  unsigned char* ciphertext = (unsigned char*)Encrypt(&en, (unsigned char*)Df.c_str(), &plaintext_len);
  string encipher( (const char*)ciphertext);

  //###############################################
  
  if(DEBUG){
    cout<<"---------------\nEncrypt data: \n"<<string_to_hex(encipher)<<endl;
    string decipher = string( Decrypt( &de, ciphertext, &plaintext_len) );
    cout<<"---------------\nDecrypt data: \n"<<decipher<<endl;
  }

  
  string y = Hash( (encipher+W[1]).c_str() );
  if(DEBUG)
    cout<<"Y: "<<y<<", with size: "<<y.size()<<endl;
  
  char tempZ[21];
  
  unsigned int zlength = 20;
  HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);
  HMAC_Init_ex(&ctx,A.c_str(),20,EVP_sha256(),NULL);
  HMAC_Update(&ctx,(const unsigned char *)y.c_str(),20);
  HMAC_Final(&ctx,(unsigned char *)tempZ,&zlength);

  tempZ[20] = '\0';
  string z(tempZ);
  LastA = A;
  if(DEBUG)
    cout<<"Z: "<<string_to_hex(z)<<", with size: "<<z.size()<<endl;


  write(Df.size(), W[1], encipher,y,z);
  cout<<"Added log entry number "<< id++<<endl;
}

void closelog(){
  string A = Hash( LastA.c_str() );
  string Df = "Close";





  //################################################
  unsigned int salt[] = {12345, 54321};
  string key_data = Hash( (W[2]+A).c_str() );
  int key_data_len = key_data.length();
  int plaintext_len = Df.length()+1;
  EVP_CIPHER_CTX en, de;

  if(DEBUG)
    cout<<"Key for Df is: "<<key_data<<", with size: "<<key_data_len<<endl;
    
  if (aes_init( (unsigned char*)key_data.c_str(), key_data_len, (unsigned char *)&salt, &en, &de)) {
    printf("Couldn't initialize AES cipher\n");
    return;
  }

  
  unsigned char* ciphertext = (unsigned char*)Encrypt(&en, (unsigned char*)Df.c_str(), &plaintext_len);
  string encipher( (const char*)ciphertext);

  //###############################################
  


  if(DEBUG){
    cout<<"---------------\nEncrypt data: \n"<<string_to_hex(encipher)<<endl;
    string decipher = string( Decrypt( &de, ciphertext, &plaintext_len) );
    cout<<"---------------\nDecrypt data: \n"<<decipher<<endl;
  }

  
  string y = Hash( (encipher+W[2]).c_str() );
  if(DEBUG)
    cout<<"Y: "<<y<<", with size: "<<y.size()<<endl;
  
  char tempZ[21];
  
  unsigned int zlength = 20;
  HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);
  HMAC_Init_ex(&ctx,A.c_str(),20,EVP_sha256(),NULL);
  HMAC_Update(&ctx,(const unsigned char *)y.c_str(),20);
  HMAC_Final(&ctx,(unsigned char *)tempZ,&zlength);

  tempZ[20] = '\0';
  string z(tempZ);
  LastA = A;
  if(DEBUG)
    cout<<"Z: "<<string_to_hex(z)<<", with size: "<<z.size()<<endl;


  write(Df.size(), W[2], encipher,y,z);
  lock = 0;
  file.close();
}

void verify(int number){
  if(DEBUG)
    cout<<"Verifying "<<number<<" entry!"<<endl;
  
  int lineID = 0;
  string last_y;
  
  int find = 0;
  string line;
  string A = A0;

  file.close();
  ifstream myfile (idlog.c_str() );
  


  if (myfile.is_open())
    {
      while ( getline (myfile,line) ){
	if(lineID == number){
	  find = 1;
	  break;
	}else if(lineID+1 == number){
	  last_y = hex_to_string( split(line,'|').at(3) );
	}
	
	lineID++;
      }
      myfile.close();
    }
 


  lineID = 0;

  while(lineID < number){
    A = Hash(A.c_str());    
    lineID++;
  }

  if(DEBUG)
    cout<<"A0: "<<string_to_hex(A0)<<", A"<<number<<": "<<string_to_hex(A)<<endl;
  


  if(find){
    vector<string> stringList = split(line,'|');
    int message_size = atoi(stringList.at(0).c_str() );
    string w = stringList.at(1);

    if( !w.compare(W[0]) || !w.compare(W[2]) )
      {
	cout<<"Invalid index!\n";
	return;
      }

    string encipher = hex_to_string( stringList.at(2) );
    string y = hex_to_string( stringList.at(3) );
    string z = hex_to_string( stringList.at(4) );

    char tempZ[21];
    unsigned int zlength = 20;
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx,A.c_str(),20,EVP_sha256(),NULL);
    HMAC_Update(&ctx,(const unsigned char *)y.c_str(),20);
    HMAC_Final(&ctx,(unsigned char *)tempZ,&zlength);
    
    tempZ[20] = '\0';
    string zC(tempZ);
    if(DEBUG)
      cout<<"-----------------\n"<<"A: "<<string_to_hex(A)<<endl<<"Y: "<<y<<endl<<"Z: "<<string_to_hex(zC)<<"\n-----------------\n";


    if( !z.compare(zC) ){
      
      //################################################
      unsigned int salt[] = {12345, 54321};
      string key_data = Hash( (w+A).c_str() );
      int key_data_len = key_data.length();
      int ciphertext_len = encipher.length()+1;
      EVP_CIPHER_CTX en, de;
      
      if(DEBUG)
	cout<<"Key for Decipher: "<<number<<" is: "<<key_data<<", with size: "<<key_data_len<<endl;
      
      if (aes_init( (unsigned char*)key_data.c_str(), key_data_len, (unsigned char *)&salt, &en, &de)) {
	printf("Couldn't initialize AES cipher\n");
	return;
      }
      
      
      string decipher = string( Decrypt( &de, (unsigned char*)encipher.c_str(), &ciphertext_len) );
      
	  
      
      //###############################################
      


      
      cout<<"Message at line: "<<number<<" is:\n-----------------\n"<<decipher<<"\n-----------------"<<endl;
    }else{
      cout<<"Failed verication"<<endl;
    }


  }else{
    cout<<"Entry number wrong!\n";

  }

  file.open(idlog.c_str(),std::ofstream::out | std::ofstream::app);

}


void verifyall(string infile, string outfile){
  if(DEBUG)
    cout<<"Reading from "<<infile<<", output to "<<outfile<<endl;


  ifstream my ("SALSCF.symm");

  if (my.is_open())
    {
      string a0((std::istreambuf_iterator<char>(my)),
		std::istreambuf_iterator<char>());
      A0 = a0;
      my.close();
    }

  
  int lineID = 0;

  string line;
  string A = A0;
  ifstream myfile (infile.c_str() );
  ofstream of( outfile.c_str() );

  if (myfile.is_open())
    {
      int count = 0;
      while ( getline (myfile,line) ){


	vector<string> stringList = split(line,'|');
	int message_size = atoi(stringList.at(0).c_str() );
	string w = stringList.at(1);
	
	string encipher = hex_to_string( stringList.at(2) );
	string y = hex_to_string( stringList.at(3) );
	string z = hex_to_string( stringList.at(4) );
	
	char tempZ[21];
	unsigned int zlength = 20;
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx,A.c_str(),20,EVP_sha256(),NULL);
	HMAC_Update(&ctx,(const unsigned char *)y.c_str(),20);
	HMAC_Final(&ctx,(unsigned char *)tempZ,&zlength);
	
	tempZ[20] = '\0';
	string zC(tempZ);
	if(DEBUG)
	  cout<<"-----------------\n"<<"A: "<<string_to_hex(A)<<endl<<"Y: "<<y<<endl<<"Z: "<<string_to_hex(zC)<<"\n-----------------\n";
	


	
	if( !z.compare(zC) ){
	  string key = Hash( (w+A).c_str() );

	  
	  
	  //################################################
	  unsigned int salt[] = {12345, 54321};
	  string key_data = Hash( (w+A).c_str() );
	  int key_data_len = key_data.length();
	  int ciphertext_len = encipher.length()+1;
	  EVP_CIPHER_CTX en, de;
      
	  if(DEBUG)
	    cout<<"Key for Decipher: "<<count++<<" is: "<<key_data<<", with size: "<<key_data_len<<endl;
	  
	  if (aes_init( (unsigned char*)key_data.c_str(), key_data_len, (unsigned char *)&salt, &en, &de)) {
	    printf("Couldn't initialize AES cipher\n");
	    return;
	  }
	  
	  
	  string decipher = string( Decrypt( &de, (unsigned char*)encipher.c_str(), &ciphertext_len) );
	  
	  

	  //###############################################
        



	  if( !w.compare(W[0]) || !w.compare(W[2]) ){
	      
	  }else{
	    of<<decipher<<endl;
	  }
	  
	}else{
	  cout<<"Failed verication"<<endl;
	}
	

	A = Hash(A.c_str());
	lineID++;
      }
      myfile.close();
    }
  else{
    cout<<"File cannot open!"<<endl;
  }


}


int main(int argc, char* argv[]){
  
  string commands;
  vector<string> commandList;
  while(true){
    cout<<"Please choose a command: createlog, add, closelog, verify, verifyall, exit."<<endl;
    getline(cin,commands);
    if(commands.compare("") == 0)
      continue;
    commandList = split(commands,' ');

    string command = commandList.at(0);
    if( command.compare("createlog") == 0){      
      if(DEBUG){
	cout<<"Command: createlog"<<endl;
      }
      
      createlog( commandList.at(1) );

    }else if( command.compare("add") == 0 ){
      if(DEBUG)
	cout<<"Command: add"<<endl;
      if(lock){
	string message = "";
	for(int i = 1 ; i < commandList.size() ; i++){
	  message.append( commandList.at(i) );
	  if( i != commandList.size() - 1)
	    message.append( " " );
	}

	add( message);
      }
    }else if( command.compare("closelog") == 0 ){
      if(DEBUG)
	cout<<"Command: closelog"<<endl;
      if(lock)
	closelog();
    }else if( command.compare("verify") == 0 ){
      if(DEBUG)
	cout<<"Command: verify"<<endl;
      if(lock)
	verify( atoi(commandList.at(1).c_str()) );

    }else if( command.compare("verifyall") == 0 ){
      if(DEBUG)
	cout<<"Command: verifyall"<<endl;
      if(!lock)
	verifyall(commandList.at(1),commandList.at(2));
    }else if( command.compare("exit") == 0 ){
      if(DEBUG)
	cout<<"Command: exit"<<endl;
      return 1;

    }else{
      cout<<"Wrong Command"<<endl;
    }
  }

}


