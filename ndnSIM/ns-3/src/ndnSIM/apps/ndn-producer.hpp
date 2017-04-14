/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2011-2015  Regents of the University of California.
 *
 * This file is part of ndnSIM. See AUTHORS for complete list of ndnSIM authors and
 * contributors.
 *
 * ndnSIM is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * ndnSIM is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndnSIM, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 **/

#ifndef NDN_PRODUCER_H
#define NDN_PRODUCER_H

#include "ns3/ndnSIM/model/ndn-common.hpp"

#include "ndn-app.hpp"
#include "ns3/ndnSIM/model/ndn-common.hpp"

#include "ns3/nstime.h"
#include "ns3/ptr.h"

// sha256 and aes
#include <cryptopp/base64.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/randpool.h>
#include <cryptopp/rsa.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

#include <string>
#include <iostream>
#include <fstream>

using namespace CryptoPP;
using namespace std;

namespace ns3 {
namespace ndn {

/**
 * @ingroup ndn-apps
 * @brief A simple Interest-sink applia simple Interest-sink application
 *
 * A simple Interest-sink applia simple Interest-sink application,
 * which replying every incoming Interest with Data packet with a specified
 * size and name same as in Interest.cation, which replying every incoming Interest
 * with Data packet with a specified size and name same as in Interest.
 */
class Producer : public App {
public:
  static TypeId
  GetTypeId(void);

  Producer();

  // inherited from NdnApp
  virtual void
  OnInterest(shared_ptr<const Interest> interest);

protected:
  // inherited from Application base class.
  virtual void
  StartApplication(); // Called at time specified by Start

  virtual void
  StopApplication(); // Called at time specified by Stop

  // char*
  // SHA256Generation(const std::string str)
  // {
  //   std::string digest;
  //   CryptoPP::SHA256 hash;

  //   CryptoPP::StringSource foo(str, true,
  //     new CryptoPP::HashFilter(hash,
  //       new CryptoPP::Base64Encoder (
  //         new CryptoPP::StringSink(digest))));
  //   return (char*)digest.c_str();
  // }

  std::string
  AESEncrypt(std::string plainText){
    byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];
    memset(key,0x00,CryptoPP::AES::DEFAULT_KEYLENGTH);
    memset(iv,0x00,CryptoPP::AES::BLOCKSIZE);

    std::string cipherText;
    CryptoPP::AES::Encryption aesEncryption(key,CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption,iv);
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption,
      new CryptoPP::StringSink(cipherText));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plainText.c_str()),
      plainText.length()+1);
    stfEncryptor.MessageEnd();
    
 
    return cipherText;
  }



  int
  compare(char* a, char* b){
    int i=0;
    while(a[i]!=0 && b[i]!=0){
      std::cout<< i << a[i] << b[i]<< std::endl;
      if (a[i]!=b[i]) return 1;
      else i++;
    }
    printf("\n");
    return 0;
  }

//RSA key generation
void 
GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed)
{
       RandomPool randPool;
       randPool.Put((byte *)seed, strlen(seed));
 
       RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);
       HexEncoder privFile(new FileSink(privFilename));
       priv.DEREncode(privFile);
       privFile.MessageEnd();
 
       RSAES_OAEP_SHA_Encryptor pub(priv);
       HexEncoder pubFile(new FileSink(pubFilename));
       pub.DEREncode(pubFile);
       pubFile.MessageEnd();
}

//RSA encryption
string 
RSAEncryptString(const char *pubFilename, const char *seed, const char *message)
{
       FileSource pubFile(pubFilename, true, new HexDecoder);
       RSAES_OAEP_SHA_Encryptor pub(pubFile);
 
       RandomPool randPool;
       randPool.Put((byte *)seed, strlen(seed));
 
       string result;
       StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(new StringSink(result))));
       return result;
}

//RSA decryption
string RSADecryptString(const char *privFilename, const char *ciphertext)
{
       FileSource privFile(privFilename, true, new HexDecoder);
       RSAES_OAEP_SHA_Decryptor priv(privFile);
 
       string result;
       StringSource(ciphertext, true, new HexDecoder(new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))));
       return result;
}

//RSA random seed
RandomPool & GlobalRNG()
{
       static RandomPool randomPool;
       return randomPool;
}

 
private:
  Name m_prefix;
  Name m_postfix;
  uint32_t m_virtualPayloadSize;
  Time m_freshness;
  uint32_t m_signature;
  Name m_keyLocator;
  std::string hashValidation;

  //rsa
  char priKey[128] = {0};
  char pubKey[128] = {0};
  char seed[1024]  = {0};
  char message[1024] = {0};

};

} // namespace ndn
} // namespace ns3

#endif // NDN_PRODUCER_H
