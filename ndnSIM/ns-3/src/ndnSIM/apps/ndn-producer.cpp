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

#include "ndn-producer.hpp"
#include "ns3/log.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"

#include "model/ndn-ns3.hpp"
#include "model/ndn-l3-protocol.hpp"
#include "helper/ndn-fib-helper.hpp"

#include <memory>
#include <string.h>
#include <chrono>
#include <iostream>

NS_LOG_COMPONENT_DEFINE("ndn.Producer");


namespace ns3 {
namespace ndn {

NS_OBJECT_ENSURE_REGISTERED(Producer);

TypeId
Producer::GetTypeId(void)
{
  static TypeId tid =
    TypeId("ns3::ndn::Producer")
      .SetGroupName("Ndn")
      .SetParent<App>()
      .AddConstructor<Producer>()
      .AddAttribute("Prefix", "Prefix, for which producer has the data", StringValue("/"),
                    MakeNameAccessor(&Producer::m_prefix), MakeNameChecker())
      .AddAttribute(
         "Postfix",
         "Postfix that is added to the output data (e.g., for adding producer-uniqueness)",
         StringValue("/"), MakeNameAccessor(&Producer::m_postfix), MakeNameChecker())
      .AddAttribute("PayloadSize", "Virtual payload size for Content packets", UintegerValue(1024),
                    MakeUintegerAccessor(&Producer::m_virtualPayloadSize),
                    MakeUintegerChecker<uint32_t>())
      .AddAttribute("Freshness", "Freshness of data packets, if 0, then unlimited freshness",
                    TimeValue(Seconds(0)), MakeTimeAccessor(&Producer::m_freshness),
                    MakeTimeChecker())
      .AddAttribute(
         "Signature",
         "Fake signature, 0 valid signature (default), other values application-specific",
         UintegerValue(0), MakeUintegerAccessor(&Producer::m_signature),
         MakeUintegerChecker<uint32_t>())
      .AddAttribute("KeyLocator",
                    "Name to be used for key locator.  If root, then key locator is not used",
                    NameValue(), MakeNameAccessor(&Producer::m_keyLocator), MakeNameChecker());
  return tid;
}

Producer::Producer()
{
  NS_LOG_FUNCTION_NOARGS();
  std::string str1=std::string(this->SHA256Generation(std::string("/company/info"))).substr(0,32);
  //std::cout<<str1<<std::endl;
  std::string str2=std::string(this->SHA256Generation(std::string("/word.pdf"))).substr(0,32);
  std::string str3=std::string(this->SHA256Generation(std::string("engineer"))).substr(0,32);
  std::string str4=std::string(this->SHA256Generation(std::string("permissionsalarydeployment"))).substr(0,32);
  std::string str5=std::string(this->SHA256Generation(str1.append(str2))).substr(0,32);
  std::string str6=std::string(this->SHA256Generation(str3.append(str4))).substr(0,32);
  this->hashValidation = std::string(this->SHA256Generation(str5.append(str6))).substr(0,32);

  //rsa
  strcpy(priKey, "pri");  // 生成的私钥文件
  strcpy(pubKey, "pub");  // 生成的公钥文件
  strcpy(seed, "seed");
  GenerateRSAKey(1024, priKey, pubKey, seed);
  strcpy(message, "Hello World!11111111111111111111111111111111111111111111111");

}

// inherited from Application base class.
void
Producer::StartApplication()
{
  NS_LOG_FUNCTION_NOARGS();
  App::StartApplication();

  FibHelper::AddRoute(GetNode(), m_prefix, m_face, 0);
}

void
Producer::StopApplication()
{
  NS_LOG_FUNCTION_NOARGS();

  App::StopApplication();
}

void
Producer::OnInterest(shared_ptr<const Interest> interest)
{
  App::OnInterest(interest); // tracing inside
  // Compute time
  // std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
  
  // NS_LOG_FUNCTION(this << interest);


  if (!m_active)
    return;

  Name dataName(interest->getName());
  auto data = make_shared<Data>();
  data->setName(dataName);
  NS_LOG_INFO("\t\t data name is " << data->getName());

  // check SID underRole
  std::string roleName="engineer";
  std::string sid = "M0419169";
  // std::cout<<roleName<<std::endl;
  // std::cout<<interest->getRoleName()<<std::endl;
  if (std::string(interest->getSID())!=sid  || std::string(interest->getRoleName()) != roleName){
    NS_LOG_INFO("\t\t"<<interest->getSID()<<"is not under role..." );
    interest.reset();
    return;
  }


  //char* hashValidation = (char*) interest->getHashValidation();
  std::string Atoken = std::string(this->SHA256Generation("M0419169MASTERKEY")).substr(0,32);
  std::ostringstream os;
  os<< interest->getNonce();
  std::string checkHashValidation= std::string(this->SHA256Generation(Atoken.append(hashValidation).append(os.str())));
  // printf("%s\n", checkHashValidation);
  // printf("%s\n", interest->getHashValidation());
  os.str()="";
  os.clear();

// this->compare(checkHashValidation,hashValidation)
  if(checkHashValidation.substr(0,16)!=std::string(interest->getHashValidation()).substr(0,16)){
    NS_LOG_INFO("\t\t Hash token Error!!!!!!!!");
    // std::chrono::steady_clock::time_point endTime = std::chrono::steady_clock::now();
    // std::cout<< std::chrono::duration_cast<std::chrono::microseconds>(endTime-startTime).count()<<"us"<<std::endl;
    // writeToCSV(std::chrono::duration_cast<std::chrono::microseconds>(endTime-startTime).count(),std::string("data/serverTokenErrorDelay.csv"));

    interest.reset();
    return;
  }
 // os.clear();
  data->setFreshnessPeriod(::ndn::time::milliseconds(m_freshness.GetMilliSeconds()));

  //data->setContent(make_shared< ::ndn::Buffer>(m_virtualPayloadSize));
  // setContent with string 
  // std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
  std::string content2 = "Hello Kitty";

 
  std::string content = AESEncrypt(std::string(content2));

  // std::chrono::steady_clock::time_point endTime = std::chrono::steady_clock::now();
  // std::cout<< std::chrono::duration_cast<std::chrono::microseconds>(endTime-startTime).count()<<"us"<<std::endl;
  data->setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.size());
  
  //std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();

  string encryptedText = RSAEncryptString(pubKey, seed, message);  // RSA 加密
  //cout<<"Encrypted Text:\t"<<encryptedText<<endl<<endl;

  Signature signature;
  SignatureInfo signatureInfo(static_cast< ::ndn::tlv::SignatureTypeValue>(255));

  if (m_keyLocator.size() > 0) {
    signatureInfo.setKeyLocator(m_keyLocator);
  }
  signature.setInfo(signatureInfo);
  signature.setValue(::ndn::nonNegativeIntegerBlock(::ndn::tlv::SignatureValue, m_signature));

  data->setSignature(signature);
  // NS_LOG_INFO("node(" << GetNode()->GetId() << ") responding with Data: " << data->getName());
  // NS_LOG_INFO("Data Content is " << readString(data->getContent()));
  // to create real wire encoding
  //std::chrono::steady_clock::time_point endTime = std::chrono::steady_clock::now();
  //std::cout<< std::chrono::duration_cast<std::chrono::microseconds>(endTime-startTime).count()<<"us"<<std::endl;

  data->wireEncode();
  // std::chrono::steady_clock::time_point endTime = std::chrono::steady_clock::now();
  // std::cout<< std::chrono::duration_cast<std::chrono::microseconds>(endTime-startTime).count()<<"us"<<std::endl;
  
  // writeToCSV(std::chrono::duration_cast<std::chrono::microseconds>(endTime-startTime).count(),std::string("data/serverDelay2.csv"));

  NS_LOG_INFO("\t\t signature"<< data->getSignature());
  m_transmittedDatas(data, this, m_face);
  m_appLink->onReceiveData(*data);
}

} // namespace ndn
} // namespace ns3
