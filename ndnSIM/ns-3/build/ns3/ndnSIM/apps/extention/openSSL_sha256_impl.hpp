#ifndef OPENSSL_SHA256_IMPL_H
#define OPENSSL_SHA256_IMPL_H

#pragma GCC system_header
#pragma clang system_header
#include <string>
namespace ns3 {

class Packet;

namespace ndn {

class openSSL_sha256_impl
{
public:
	openSSL_sha256_impl();
	virtual ~openSSL_sha256_impl();

	std::string 
	sha256(const std::string str);
};
}
}
#endif