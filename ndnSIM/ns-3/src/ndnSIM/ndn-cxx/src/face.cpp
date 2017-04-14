/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2015 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#include "face.hpp"
#include "detail/face-impl.hpp"

#include "encoding/tlv.hpp"
#include "security/key-chain.hpp"
#include "security/signing-helpers.hpp"
#include "util/time.hpp"
#include "util/random.hpp"
#include "util/face-uri.hpp"

#include "ns3/node-list.h"
#include "ns3/ndnSIM/helper/ndn-stack-helper.hpp"
#include "ns3/ndnSIM/NFD/daemon/face/generic-link-service.hpp"
#include "ns3/ndnSIM/NFD/daemon/face/internal-transport.hpp"

namespace ndn {

Face::Face()
  : m_impl(new Impl(*this))
{
  construct(nullptr, ns3::ndn::StackHelper::getKeyChain());
}

Face::Face(boost::asio::io_service& ioService)
  : m_impl(new Impl(*this))
{
  construct(nullptr, ns3::ndn::StackHelper::getKeyChain());
}

Face::Face(shared_ptr<Transport> transport)
  : m_impl(new Impl(*this))
{
  construct(transport, ns3::ndn::StackHelper::getKeyChain());
}

Face::Face(shared_ptr<Transport> transport,
           boost::asio::io_service& ioService)
  : m_impl(new Impl(*this))
{
  construct(transport, ns3::ndn::StackHelper::getKeyChain());
}

Face::Face(shared_ptr<Transport> transport,
           boost::asio::io_service& ioService,
           KeyChain& keyChain)
  : m_impl(new Impl(*this))
{
  construct(transport, keyChain);
}

shared_ptr<Transport>
Face::makeDefaultTransport()
{
  ns3::Ptr<ns3::Node> node = ns3::NodeList::GetNode(ns3::Simulator::GetContext());
  NS_ASSERT_MSG(node->GetObject<ns3::ndn::L3Protocol>() != 0,
                "NDN stack should be installed on the node " << node);

  auto uri = ::nfd::FaceUri("ndnFace://" + boost::lexical_cast<std::string>(node->GetId()));

  ::nfd::face::GenericLinkService::Options serviceOpts;
  serviceOpts.allowLocalFields = true;

  auto nfdFace = make_shared<::nfd::Face>(make_unique<::nfd::face::GenericLinkService>(serviceOpts),
                                          make_unique<::nfd::face::InternalForwarderTransport>(uri, uri));
  auto forwarderTransport = static_cast<::nfd::face::InternalForwarderTransport*>(nfdFace->getTransport());

  auto clientTransport = make_shared<::nfd::face::InternalClientTransport>();
  clientTransport->connectToForwarder(forwarderTransport);

  node->GetObject<ns3::ndn::L3Protocol>()->addFace(nfdFace);;

  return clientTransport;
}

void
Face::construct(shared_ptr<Transport> transport, KeyChain& keyChain)
{
  if (transport == nullptr) {
    transport = makeDefaultTransport();
  }
  BOOST_ASSERT(transport != nullptr);
  m_transport = transport;

  m_nfdController.reset(new nfd::Controller(*this, keyChain));
}

Face::~Face() = default;

shared_ptr<Transport>
Face::getTransport()
{
  return m_transport;
}

const PendingInterestId*
Face::expressInterest(const Interest& interest,
                      const DataCallback& afterSatisfied,
                      const NackCallback& afterNacked,
                      const TimeoutCallback& afterTimeout)
{
  shared_ptr<Interest> interestToExpress = make_shared<Interest>(interest);

  // Use `interestToExpress` to avoid wire format creation for the original Interest
  if (interestToExpress->wireEncode().size() > MAX_NDN_PACKET_SIZE) {
    BOOST_THROW_EXCEPTION(Error("Interest size exceeds maximum limit"));
  }

  // If the same ioService thread, dispatch directly calls the method
  m_impl->m_scheduler.scheduleEvent(time::seconds(0), [=] {
      m_impl->asyncExpressInterest(interestToExpress, afterSatisfied,
                                   afterNacked, afterTimeout);
    });

  return reinterpret_cast<const PendingInterestId*>(interestToExpress.get());
}

const PendingInterestId*
Face::expressInterest(const Interest& interest,
                      const OnData& onData,
                      const OnTimeout& onTimeout)
{
  return this->expressInterest(
    interest,
    [onData] (const Interest& interest, const Data& data) {
      if (onData != nullptr) {
        onData(interest, const_cast<Data&>(data));
      }
    },
    [onTimeout] (const Interest& interest, const lp::Nack& nack) {
      if (onTimeout != nullptr) {
        onTimeout(interest);
      }
    },
    onTimeout
  );
}

const PendingInterestId*
Face::expressInterest(const Name& name,
                      const Interest& tmpl,
                      const OnData& onData, const OnTimeout& onTimeout/* = nullptr*/)
{
  return expressInterest(Interest(tmpl)
                         .setName(name)
                         .setNonce(0),
                         onData, onTimeout);
}

void
Face::put(const Data& data)
{
  // Use original `data`, since wire format should already exist for the original Data
  if (data.wireEncode().size() > MAX_NDN_PACKET_SIZE)
    BOOST_THROW_EXCEPTION(Error("Data size exceeds maximum limit"));

  shared_ptr<const Data> dataPtr;
  try {
    dataPtr = data.shared_from_this();
  }
  catch (const bad_weak_ptr& e) {
    std::cerr << "Face::put WARNING: the supplied Data should be created using make_shared<Data>()"
              << std::endl;
    dataPtr = make_shared<Data>(data);
  }

  // If the same ioService thread, dispatch directly calls the method
  m_impl->m_scheduler.scheduleEvent(time::seconds(0), [=] { m_impl->asyncPutData(dataPtr); });
}

void
Face::put(const lp::Nack& nack)
{
  m_impl->m_scheduler.scheduleEvent(time::seconds(0), [=] { m_impl->asyncPutNack(make_shared<lp::Nack>(nack)); });
}

void
Face::removePendingInterest(const PendingInterestId* pendingInterestId)
{
  m_impl->m_scheduler.scheduleEvent(time::seconds(0), [=] { m_impl->asyncRemovePendingInterest(pendingInterestId); });
}

void
Face::removeAllPendingInterests()
{
  m_impl->m_scheduler.scheduleEvent(time::seconds(0), [=] { m_impl->asyncRemoveAllPendingInterests(); });
}

size_t
Face::getNPendingInterests() const
{
  return m_impl->m_pendingInterestTable.size();
}

const RegisteredPrefixId*
Face::setInterestFilter(const InterestFilter& interestFilter,
                  const OnInterest& onInterest,
                  const RegisterPrefixFailureCallback& onFailure,
                  const security::SigningInfo& signingInfo,
                  uint64_t flags)
{
    return setInterestFilter(interestFilter,
                             onInterest,
                             RegisterPrefixSuccessCallback(),
                             onFailure,
                             signingInfo,
                             flags);
}

const RegisteredPrefixId*
Face::setInterestFilter(const InterestFilter& interestFilter,
                  const OnInterest& onInterest,
                  const RegisterPrefixSuccessCallback& onSuccess,
                  const RegisterPrefixFailureCallback& onFailure,
                  const security::SigningInfo& signingInfo,
                  uint64_t flags)
{
    shared_ptr<InterestFilterRecord> filter =
      make_shared<InterestFilterRecord>(interestFilter, onInterest);

    nfd::CommandOptions options;
    options.setSigningInfo(signingInfo);

    return m_impl->registerPrefix(interestFilter.getPrefix(), filter,
                                  onSuccess, onFailure,
                                  flags, options);
}

const InterestFilterId*
Face::setInterestFilter(const InterestFilter& interestFilter,
                        const OnInterest& onInterest)
{
  shared_ptr<InterestFilterRecord> filter =
    make_shared<InterestFilterRecord>(interestFilter, onInterest);

  m_impl->m_scheduler.scheduleEvent(time::seconds(0), [=] {
      m_impl->asyncSetInterestFilter(filter);
    });

  return reinterpret_cast<const InterestFilterId*>(filter.get());
}

#ifdef NDN_FACE_KEEP_DEPRECATED_REGISTRATION_SIGNING

const RegisteredPrefixId*
Face::setInterestFilter(const InterestFilter& interestFilter,
                        const OnInterest& onInterest,
                        const RegisterPrefixSuccessCallback& onSuccess,
                        const RegisterPrefixFailureCallback& onFailure,
                        const IdentityCertificate& certificate,
                        uint64_t flags)
{
  security::SigningInfo signingInfo;
  if (!certificate.getName().empty()) {
    signingInfo = signingByCertificate(certificate.getName());
  }
  return setInterestFilter(interestFilter, onInterest,
                           onSuccess, onFailure,
                           signingInfo, flags);
}

const RegisteredPrefixId*
Face::setInterestFilter(const InterestFilter& interestFilter,
                        const OnInterest& onInterest,
                        const RegisterPrefixFailureCallback& onFailure,
                        const IdentityCertificate& certificate,
                        uint64_t flags)
{
  security::SigningInfo signingInfo;
  if (!certificate.getName().empty()) {
    signingInfo = signingByCertificate(certificate.getName());
  }
  return setInterestFilter(interestFilter, onInterest,
                             onFailure, signingInfo, flags);
}

const RegisteredPrefixId*
Face::setInterestFilter(const InterestFilter& interestFilter,
                        const OnInterest& onInterest,
                        const RegisterPrefixSuccessCallback& onSuccess,
                        const RegisterPrefixFailureCallback& onFailure,
                        const Name& identity,
                        uint64_t flags)
{
  security::SigningInfo signingInfo = signingByIdentity(identity);

  return setInterestFilter(interestFilter, onInterest,
                           onSuccess, onFailure,
                           signingInfo, flags);
}

const RegisteredPrefixId*
Face::setInterestFilter(const InterestFilter& interestFilter,
                        const OnInterest& onInterest,
                        const RegisterPrefixFailureCallback& onFailure,
                        const Name& identity,
                        uint64_t flags)
{
  security::SigningInfo signingInfo = signingByIdentity(identity);

  return setInterestFilter(interestFilter, onInterest,
                           onFailure, signingInfo, flags);
}

#endif // NDN_FACE_KEEP_DEPRECATED_REGISTRATION_SIGNING

const RegisteredPrefixId*
Face::registerPrefix(const Name& prefix,
               const RegisterPrefixSuccessCallback& onSuccess,
               const RegisterPrefixFailureCallback& onFailure,
               const security::SigningInfo& signingInfo,
               uint64_t flags)
{

    nfd::CommandOptions options;
    options.setSigningInfo(signingInfo);

    return m_impl->registerPrefix(prefix, shared_ptr<InterestFilterRecord>(),
                                  onSuccess, onFailure,
                                  flags, options);
}

#ifdef NDN_FACE_KEEP_DEPRECATED_REGISTRATION_SIGNING
const RegisteredPrefixId*
Face::registerPrefix(const Name& prefix,
                     const RegisterPrefixSuccessCallback& onSuccess,
                     const RegisterPrefixFailureCallback& onFailure,
                     const IdentityCertificate& certificate,
                     uint64_t flags)
{
  security::SigningInfo signingInfo;
  if (!certificate.getName().empty()) {
    signingInfo = signingByCertificate(certificate.getName());
  }
  return registerPrefix(prefix, onSuccess,
                        onFailure, signingInfo, flags);
}

const RegisteredPrefixId*
Face::registerPrefix(const Name& prefix,
                     const RegisterPrefixSuccessCallback& onSuccess,
                     const RegisterPrefixFailureCallback& onFailure,
                     const Name& identity,
                     uint64_t flags)
{
  security::SigningInfo signingInfo = signingByIdentity(identity);
  return registerPrefix(prefix, onSuccess,
                        onFailure, signingInfo, flags);
}
#endif // NDN_FACE_KEEP_DEPRECATED_REGISTRATION_SIGNING

void
Face::unsetInterestFilter(const RegisteredPrefixId* registeredPrefixId)
{
  m_impl->m_scheduler.scheduleEvent(time::seconds(0), [=] { m_impl->asyncUnregisterPrefix(registeredPrefixId,
                                                       UnregisterPrefixSuccessCallback(),
                                                       UnregisterPrefixFailureCallback()); });
}

void
Face::unsetInterestFilter(const InterestFilterId* interestFilterId)
{
  m_impl->m_scheduler.scheduleEvent(time::seconds(0), [=] { m_impl->asyncUnsetInterestFilter(interestFilterId); });
}

void
Face::unregisterPrefix(const RegisteredPrefixId* registeredPrefixId,
                       const UnregisterPrefixSuccessCallback& onSuccess,
                       const UnregisterPrefixFailureCallback& onFailure)
{
  m_impl->m_scheduler.scheduleEvent(time::seconds(0), [=] { m_impl->asyncUnregisterPrefix(registeredPrefixId,onSuccess, onFailure); });
}

void
Face::processEvents(const time::milliseconds& timeout/* = time::milliseconds::zero()*/,
                    bool keepThread/* = false*/)
{
}

void
Face::shutdown()
{
  m_impl->m_scheduler.scheduleEvent(time::seconds(0), [this] { this->asyncShutdown(); });
}

void
Face::asyncShutdown()
{
  m_impl->m_pendingInterestTable.clear();
  m_impl->m_registeredPrefixTable.clear();

  if (m_transport->isConnected())
    m_transport->close();
}

/**
 * @brief extract local fields from NDNLPv2 packet and tag onto a network layer packet
 */
template<typename NETPKT>
static void
extractLpLocalFields(NETPKT& netPacket, const lp::Packet& lpPacket)
{
  if (lpPacket.has<lp::IncomingFaceIdField>()) {
    netPacket.setTag(make_shared<lp::IncomingFaceIdTag>(lpPacket.get<lp::IncomingFaceIdField>()));
  }
}

void
Face::onReceiveElement(const Block& blockFromDaemon)
{
  lp::Packet lpPacket(blockFromDaemon); // bare Interest/Data is a valid lp::Packet,
                                        // no need to distinguish

  Buffer::const_iterator begin, end;
  std::tie(begin, end) = lpPacket.get<lp::FragmentField>();
  Block netPacket(&*begin, std::distance(begin, end));
  switch (netPacket.type()) {
    case tlv::Interest: {
      shared_ptr<Interest> interest = make_shared<Interest>(netPacket);
      if (lpPacket.has<lp::NackField>()) {
        auto nack = make_shared<lp::Nack>(std::move(*interest));
        nack->setHeader(lpPacket.get<lp::NackField>());
        extractLpLocalFields(*nack, lpPacket);
        m_impl->nackPendingInterests(*nack);
      }
      else {
        extractLpLocalFields(*interest, lpPacket);
        m_impl->processInterestFilters(*interest);
      }
      break;
    }
    case tlv::Data: {
      shared_ptr<Data> data = make_shared<Data>(netPacket);
      extractLpLocalFields(*data, lpPacket);
      m_impl->satisfyPendingInterests(*data);
      break;
    }
  }
}

} // namespace ndn
