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

#ifndef NDN_APP_H
#define NDN_APP_H

#include "ns3/ndnSIM/model/ndn-common.hpp"
#include "ns3/ndnSIM/model/ndn-app-link-service.hpp"
#include "ns3/ndnSIM/NFD/daemon/face/face.hpp"

#include "ns3/application.h"
#include "ns3/ptr.h"
#include "ns3/callback.h"
#include "ns3/traced-callback.h"

// sha256 and aes
#include <cryptopp/base64.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <fstream>

#include <string>


namespace ns3 {

class Packet;

namespace ndn {

/**
 * \ingroup ndn
 * \defgroup ndn-apps NDN applications
 */
/**
 * @ingroup ndn-apps
 * @brief Base class that all NDN applications should be derived from.
 *
 * The class implements virtual calls onInterest, onNack, and onData
 */
class App : public Application {
public:
  static TypeId
  GetTypeId();

  /**
   * @brief Default constructor
   */
  App();
  virtual ~App();

  /**
   * @brief Get application ID (ID of applications face)
   */
  uint32_t
  GetId() const;

  /**
   * @brief Method that will be called every time new Interest arrives
   */
  virtual void
  OnInterest(shared_ptr<const Interest> interest);

  /**
   * @brief Method that will be called every time new Data arrives
   */
  virtual void
  OnData(shared_ptr<const Data> data);

   /**
   * @brief Method that will be called every time new Nack arrives
   */
  virtual void
  OnNack(shared_ptr<const lp::Nack> nack);

public:
  typedef void (*InterestTraceCallback)(shared_ptr<const Interest>, Ptr<App>, shared_ptr<Face>);
  typedef void (*DataTraceCallback)(shared_ptr<const Data>, Ptr<App>, shared_ptr<Face>);
  // @TODO add NACK
  

  char*
  SHA256Generation(std::string str)
  {
    // std::string digest;
    // CryptoPP::SHA256 hash;

    // CryptoPP::StringSource foo(str, true,
    //   new CryptoPP::HashFilter(hash,
    //     new CryptoPP::Base64Encoder (
    //       new CryptoPP::StringSink(digest))));
    // return (char*)digest.c_str();
    byte digest[CryptoPP::SHA256::DIGESTSIZE];
    CryptoPP::SHA256().CalculateDigest(digest, (byte*) &str[0], str.size());
    std::string ret;
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(ret));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();
    
    return (char*)ret.c_str();
  }

   static void writeToCSV(int time,std::string str){
    std::ofstream fp;
    fp.open(str,std::ios::app);
    fp<<time<<",\t"<<std::endl;
    fp.close();
  }

protected:
  virtual void
  DoInitialize();

  virtual void
  DoDispose();

  // inherited from Application base class. Originally they were private
  virtual void
  StartApplication(); ///< @brief Called at time specified by Start

  virtual void
  StopApplication(); ///< @brief Called at time specified by Stop

protected:
  bool m_active; ///< @brief Flag to indicate that application is active (set by StartApplication and StopApplication)
  shared_ptr<Face> m_face;
  AppLinkService* m_appLink;

  uint32_t m_appId;

  TracedCallback<shared_ptr<const Interest>, Ptr<App>, shared_ptr<Face>>
    m_receivedInterests; ///< @brief App-level trace of received Interests

  TracedCallback<shared_ptr<const Data>, Ptr<App>, shared_ptr<Face>>
    m_receivedDatas; ///< @brief App-level trace of received Data

  // @TODO add NACK

  TracedCallback<shared_ptr<const Interest>, Ptr<App>, shared_ptr<Face>>
    m_transmittedInterests; ///< @brief App-level trace of transmitted Interests

  TracedCallback<shared_ptr<const Data>, Ptr<App>, shared_ptr<Face>>
    m_transmittedDatas; ///< @brief App-level trace of transmitted Data

  // @TODO add NACK
};

} // namespace ndn
} // namespace ns3

#endif // NDN_APP_H
