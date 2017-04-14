#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/ndnSIM-module.h"
#include <time.h>


namespace ns3 {

int
main(int argc, char* argv[])
{
  // setting default parameters for PointToPoint links and channels
  Config::SetDefault("ns3::PointToPointNetDevice::DataRate", StringValue("1Mbps"));
  Config::SetDefault("ns3::PointToPointChannel::Delay", StringValue("10ms"));
  Config::SetDefault("ns3::DropTailQueue::MaxPackets", StringValue("20"));
  // Config::Set ("/NodeList/1/$ns3::ndn::ContentStore/MaxSize", UintegerValue (10));

  // Read optional command-line parameters (e.g., enable visualizer with ./waf --run=<> --visualize
  CommandLine cmd;
  cmd.Parse(argc, argv);

  // Creating nodes
  NodeContainer nodes;
  nodes.Create(4);

  // Connecting nodes using two links
  PointToPointHelper p2p;
  p2p.Install(nodes.Get(0), nodes.Get(1));
  p2p.Install(nodes.Get(1), nodes.Get(2));
  p2p.Install(nodes.Get(3), nodes.Get(1));
  p2p.Install(nodes.Get(3), nodes.Get(2));

  // Install NDN stack on all nodes
  ndn::StackHelper ndnHelper;
  ndnHelper.SetDefaultRoutes(true);
  //Content store in the middle NDN router
  ndnHelper.SetOldContentStore("ns3::ndn::cs::Lru","MaxSize","100");
  ndnHelper.InstallAll();

  // Choosing forwarding strategy
  ndn::StrategyChoiceHelper::InstallAll("/company/info/", "/localhost/nfd/strategy/best-route");

  // Installing applications

  // Consumer0
  ndn::AppHelper consumerHelper("ns3::ndn::ConsumerCbr");
  // Consumer will request /prefix/0, /prefix/1, ...
  consumerHelper.SetPrefix("/company/info");
  consumerHelper.SetAttribute("Frequency", StringValue("1")); // 10 interests a second
  consumerHelper.Install(nodes.Get(0));                        // first node

  // // Consumer1
  ndn::AppHelper consumerHelper2("ns3::ndn::ConsumerCbr2");
  consumerHelper2.SetPrefix("/company/info");
  consumerHelper2.SetAttribute("Frequency", StringValue("1"));
  consumerHelper2.Install(nodes.Get(3)).Start(Seconds(0.5));

  // Producer
  ndn::AppHelper producerHelper("ns3::ndn::Producer");
  // producerHelper.SetAttribute("Freshness", TimeValue(Seconds(10.0))); // freshness 2 seconds (!!!
  // Producer will reply to all requests starting with /prefix
  producerHelper.SetPrefix("/company/info");
  producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
  producerHelper.Install(nodes.Get(2)); // last node

  
  //ndn::CsTracer::InstallAll("cs-trace.txt", Seconds(1));

  Simulator::Stop(Seconds(10));

  Simulator::Run();
  Simulator::Destroy();

  return 0;
}

} // namespace ns3

int
main(int argc, char* argv[])
{ 
  ns3::main(argc, argv);
  return 0;
}
