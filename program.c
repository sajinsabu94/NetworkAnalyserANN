 // The Topology contains 6 nodes as follows:
 // 0 -> normal machine
 // 1 -> attacker
 // 2 -> switch (common switch between attacker and normal machine)
 // 3 -> switch (switch conneced to company)
 // 4 -> detection server
 // 5 -> main receiver
 /*
		    n1
		       \ pp1 (3Mbps, 10ms RTT)
			\
			 \             
			  \            
                          n2 ---------------------------- n3   n4   n5
			  /            |                   |    |    |
			 /             |                   ===========
                        /              |                        |
		       /               |                        ---------> csma (2Mbps, 2ms)
		      /                |
		     /                 -> pp2 (5Mbps, 2ms RTT)
		    /
		   / ---> pp1 (3Mbps, 10ms RTT)
		  n0
		 
*/


#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/csma-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"
#include "ns3/tap-bridge-helper.h"
#include "ns3/emu-fd-net-device-helper.h"
#include <iomanip>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include "ns3/gnuplot.h"

#define TCP_SINK_PORT 9000
#define UDP_SINK_PORT 9001
#define BULK_SEND_MAX_BYTES 999999999
uint16_t port = 9;

using namespace ns3;
NS_LOG_COMPONENT_DEFINE ("ProjectModel");

void attackUDP(OnOffHelper onoff, NodeContainer c, int n){
  onoff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
  onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
  onoff.SetAttribute ("DataRate", StringValue ("5Mbps"));
  onoff.SetAttribute ("PacketSize", UintegerValue (100));

  ApplicationContainer apps = onoff.Install (c.Get (n));
  apps.Start (Seconds (10.0));
  apps.Stop (Seconds (30.0));
}

int
main (int argc, char *argv[])
{
  // set time resolution of simulation  
  // By default, it is disabled.  To respond to interface events, set to true
  Config::SetDefault ("ns3::Ipv4GlobalRouting::RespondToInterfaceEvents", BooleanValue (true));

  GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::RealtimeSimulatorImpl"));
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  CommandLine cmd;
  cmd.Parse (argc, argv);
  
  Time::SetResolution (Time::NS);
  LogComponentEnable ("UdpEchoClientApplication", LOG_LEVEL_INFO);
  LogComponentEnable ("UdpEchoServerApplication", LOG_LEVEL_INFO);

  std::string fileNameWithNoExtension = "FlowVSThroughput";
  std::string graphicsFileName        = fileNameWithNoExtension + ".png";
  std::string plotFileName            = fileNameWithNoExtension + ".plt";
  std::string plotTitle               = "Flow vs Throughput";
  std::string dataTitle               = "Throughput";

  // Instantiate the plot and set its title.
  Gnuplot gnuplot (graphicsFileName);
  gnuplot.SetTitle (plotTitle);

  // Make the graphics file, which the plot file will be when it
  // is used with Gnuplot, be a PNG file.
  gnuplot.SetTerminal ("png");

  // Set the labels for each axis.
  gnuplot.SetLegend ("Flow", "Throughput");

  Gnuplot2dDataset dataset;
  dataset.SetTitle (dataTitle);
  dataset.SetStyle (Gnuplot2dDataset::LINES_POINTS);


  // define Internet helpers
  InternetStackHelper internet;

  NS_LOG_INFO ("Create nodes.");
  NodeContainer c;
  c.Create (30);

  // Compose internetwork node mobility
/*
  MobilityHelper mobilityHelper1;
  Ptr<ListPositionAllocator> listPositionAllocator1 = CreateObject<ListPositionAllocator> ();
  mobilityHelper1.SetPositionAllocator (listPositionAllocator1);
  mobilityHelper1.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  listPositionAllocator1->Add ( Vector(-40.0, 20.0, 0.0));
  mobilityHelper1.Install (c.Get(0));

  MobilityHelper mobilityHelper2;
  Ptr<ListPositionAllocator> listPositionAllocator2 = CreateObject<ListPositionAllocator> ();
  mobilityHelper2.SetPositionAllocator (listPositionAllocator2);
  mobilityHelper2.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  listPositionAllocator2->Add ( Vector(-40.0, -20.0, 0.0));
  mobilityHelper2.Install (c.Get(1));

  MobilityHelper mobilityHelper3;
  Ptr<ListPositionAllocator> listPositionAllocator3 = CreateObject<ListPositionAllocator> ();
  mobilityHelper3.SetPositionAllocator (listPositionAllocator3);
  mobilityHelper3.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  listPositionAllocator3->Add ( Vector(-20.0, 0.0, 0.0));
  mobilityHelper3.Install (c.Get(2));
 
  MobilityHelper mobilityHelper4;
  Ptr<ListPositionAllocator> listPositionAllocator4 = CreateObject<ListPositionAllocator> ();
  mobilityHelper4.SetPositionAllocator (listPositionAllocator4);
  mobilityHelper4.SetMobilityModel ("ns3::ConstantPositionMobilityModel");   
  listPositionAllocator4->Add ( Vector(0.0, 0.0, 0.0));
  mobilityHelper4.Install (c.Get(3));
  
  MobilityHelper mobilityHelper5;
  Ptr<ListPositionAllocator> listPositionAllocator5 = CreateObject<ListPositionAllocator> ();
  mobilityHelper5.SetPositionAllocator (listPositionAllocator5);
  mobilityHelper5.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  listPositionAllocator5->Add ( Vector(30.0, 20.0, 0.0));
  mobilityHelper5.Install (c.Get(4));
  
  MobilityHelper mobilityHelper6;
  Ptr<ListPositionAllocator> listPositionAllocator6 = CreateObject<ListPositionAllocator> ();
  mobilityHelper6.SetPositionAllocator (listPositionAllocator6);
  mobilityHelper6.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  listPositionAllocator6->Add ( Vector(30.0, -20.0, 0.0));
  mobilityHelper6.Install (c.Get(5));
*/
  EmuFdNetDeviceHelper emu;
  std::string deviceName ("enp1s0");
  emu.SetDeviceName(deviceName);

  NodeContainer n0n21 = NodeContainer (c.Get (0), c.Get (21));
  NodeContainer n1n21 = NodeContainer (c.Get (1), c.Get (21));
  NodeContainer n2n21 = NodeContainer (c.Get (2), c.Get (21));
  NodeContainer n3n21 = NodeContainer (c.Get (3), c.Get (21));
  NodeContainer n4n21 = NodeContainer (c.Get (4), c.Get (21));
  NodeContainer n5n21 = NodeContainer (c.Get (5), c.Get (21));
  NodeContainer n6n21 = NodeContainer (c.Get (6), c.Get (21));
  NodeContainer n7n21 = NodeContainer (c.Get (7), c.Get (21));
  NodeContainer n8n21 = NodeContainer (c.Get (8), c.Get (21));
  NodeContainer n9n21 = NodeContainer (c.Get (9), c.Get (21));
  NodeContainer n10n21 = NodeContainer (c.Get (10), c.Get (21));
  NodeContainer n11n21 = NodeContainer (c.Get (11), c.Get (21));
  NodeContainer n12n21 = NodeContainer (c.Get (12), c.Get (21));
  NodeContainer n13n21 = NodeContainer (c.Get (13), c.Get (21));
  NodeContainer n14n21 = NodeContainer (c.Get (14), c.Get (21));
  NodeContainer n15n21 = NodeContainer (c.Get (15), c.Get (21));
  NodeContainer n16n21 = NodeContainer (c.Get (16), c.Get (21));
  NodeContainer n17n21 = NodeContainer (c.Get (17), c.Get (21));
  NodeContainer n18n21 = NodeContainer (c.Get (18), c.Get (21));
  NodeContainer n19n21 = NodeContainer (c.Get (19), c.Get (21));
  NodeContainer n20n21 = NodeContainer (c.Get (20), c.Get (21));

  NodeContainer n2n3 = NodeContainer (c.Get (21), c.Get (22));
  NodeContainer n345 = NodeContainer (c.Get (22), c.Get (23), c.Get (24));

  NodeContainer nLocal = NodeContainer (c.Get (24), c.Get (25));
  nLocal.Add(c.Get (26));
  nLocal.Add(c.Get (27));
  nLocal.Add(c.Get (28));
  nLocal.Add(c.Get (29));

  // Compose internetworking

  // Add IP protocol stack to network nodes
  internet.Install (c);

  // Compose p2p links
  NS_LOG_INFO ("Create channels.");
  PointToPointHelper p2p;
  p2p.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
  p2p.SetChannelAttribute ("Delay", StringValue ("10ms"));

  NetDeviceContainer d0d21 = p2p.Install (n0n21);
  NetDeviceContainer d1d21 = p2p.Install (n1n21);
  NetDeviceContainer d2d21 = p2p.Install (n2n21);
  NetDeviceContainer d3d21 = p2p.Install (n3n21);
  NetDeviceContainer d4d21 = p2p.Install (n4n21);
  NetDeviceContainer d5d21 = p2p.Install (n5n21);
  NetDeviceContainer d6d21 = p2p.Install (n6n21);
  NetDeviceContainer d7d21 = p2p.Install (n7n21);
  NetDeviceContainer d8d21 = p2p.Install (n8n21);
  NetDeviceContainer d9d21 = p2p.Install (n9n21);
  NetDeviceContainer d10d21 = p2p.Install (n10n21);
  NetDeviceContainer d11d21 = p2p.Install (n11n21);
  NetDeviceContainer d12d21 = p2p.Install (n12n21);
  NetDeviceContainer d13d21 = p2p.Install (n13n21);
  NetDeviceContainer d14d21 = p2p.Install (n14n21);
  NetDeviceContainer d15d21 = p2p.Install (n15n21);
  NetDeviceContainer d16d21 = p2p.Install (n16n21);
  NetDeviceContainer d17d21 = p2p.Install (n17n21);
  NetDeviceContainer d18d21 = p2p.Install (n18n21);
  NetDeviceContainer d19d21 = p2p.Install (n19n21);
  NetDeviceContainer d1d2 = p2p.Install (n20n21);

  p2p.SetDeviceAttribute ("DataRate", StringValue ("50Mbps"));
  p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));
  NetDeviceContainer d2d3 = p2p.Install (n2n3);

   // Compose CSMA network associated with CSMA channel
  CsmaHelper csma;
  csma.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
  csma.SetChannelAttribute ("Delay", StringValue ("2ms"));
  NetDeviceContainer d345 = csma.Install (n345);

   // Compose CSMA network associated with CSMA channel
  CsmaHelper csmaLocal;
  csma.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
  csma.SetChannelAttribute ("Delay", StringValue ("2ms"));
  NetDeviceContainer dLocal = csma.Install (nLocal);


  // assign IP addresses for bidirectional links
  NS_LOG_INFO ("Assign IP Addresses.");
  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i0i21 = ipv4.Assign (d0d21);
  ipv4.SetBase ("10.2.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i1i21 = ipv4.Assign (d1d21);
  ipv4.SetBase ("10.3.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i2i21 = ipv4.Assign (d2d21);
  ipv4.SetBase ("10.4.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i3i21 = ipv4.Assign (d3d21);
  ipv4.SetBase ("10.5.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i4i21 = ipv4.Assign (d4d21);
  ipv4.SetBase ("10.6.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i5i21 = ipv4.Assign (d5d21);
  ipv4.SetBase ("10.7.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i6i21 = ipv4.Assign (d6d21);
  ipv4.SetBase ("10.8.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i7i21 = ipv4.Assign (d7d21);
  ipv4.SetBase ("10.9.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i8i21 = ipv4.Assign (d8d21);
  ipv4.SetBase ("10.10.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i9i21 = ipv4.Assign (d9d21);
  ipv4.SetBase ("10.11.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i10i21 = ipv4.Assign (d10d21);
  ipv4.SetBase ("10.12.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i11i21 = ipv4.Assign (d11d21);
  ipv4.SetBase ("10.13.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i12i21 = ipv4.Assign (d12d21);
  ipv4.SetBase ("10.14.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i13i21 = ipv4.Assign (d13d21);
  ipv4.SetBase ("10.15.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i14i21 = ipv4.Assign (d14d21);
  ipv4.SetBase ("10.16.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i15i21 = ipv4.Assign (d15d21);
  ipv4.SetBase ("10.17.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i16i21 = ipv4.Assign (d16d21);
  ipv4.SetBase ("10.18.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i17i21 = ipv4.Assign (d17d21);
  ipv4.SetBase ("10.19.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i18i21 = ipv4.Assign (d18d21);
  ipv4.SetBase ("10.20.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i19i21 = ipv4.Assign (d19d21);
//  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
//  ipv4.SetBase ("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer i1i2 = ipv4.Assign (d1d2);

  ipv4.SetBase ("10.1.3.0", "255.255.255.0");
  Ipv4InterfaceContainer i2i3 = ipv4.Assign (d2d3);

  ipv4.SetBase ("10.1.4.0", "255.255.255.0");
  Ipv4InterfaceContainer i345 = ipv4.Assign (d345);

  ipv4.SetBase ("10.1.5.0", "255.255.255.0");
  Ipv4InterfaceContainer iLocal = ipv4.Assign (dLocal);

  // assign and populate global centralized routing "God" tables
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  // Compose applications



  BulkSendHelper bulkSend ("ns3::TcpSocketFactory", InetSocketAddress (i345.GetAddress (2), TCP_SINK_PORT));
  bulkSend.SetAttribute ("MaxBytes", UintegerValue (BULK_SEND_MAX_BYTES));
  ApplicationContainer bulkSendApp = bulkSend.Install (c.Get (0));
  bulkSendApp.Start (Seconds (2.0));
  bulkSendApp.Stop (Seconds (30.0));

  BulkSendHelper bulkSend2 ("ns3::TcpSocketFactory", InetSocketAddress (i345.GetAddress (2), TCP_SINK_PORT));
  bulkSend2.SetAttribute ("MaxBytes", UintegerValue (BULK_SEND_MAX_BYTES));
  ApplicationContainer bulkSendApp2 = bulkSend2.Install (c.Get (8));
  bulkSendApp2.Start (Seconds (2.0));
  bulkSendApp2.Stop (Seconds (30.0));

  PacketSinkHelper TCPsink ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), TCP_SINK_PORT));
  ApplicationContainer TCPSinkApp = TCPsink.Install (c.Get (24));
  TCPSinkApp.Start (Seconds (1.0));
  TCPSinkApp.Stop (Seconds (30.0));



  // Create the OnOff application to send UDP datagrams of size
  NS_LOG_INFO ("Create Applications.");

  OnOffHelper onoff ("ns3::UdpSocketFactory", InetSocketAddress (i345.GetAddress (2), port));
  attackUDP(onoff, c, 1);

  OnOffHelper onoff1 ("ns3::UdpSocketFactory", InetSocketAddress (i345.GetAddress (2), port));
  attackUDP(onoff1, c, 2);

  OnOffHelper onoff2 ("ns3::UdpSocketFactory", InetSocketAddress (i345.GetAddress (2), port));
  attackUDP(onoff2, c, 3);

  OnOffHelper onoff3 ("ns3::UdpSocketFactory", InetSocketAddress (i345.GetAddress (2), port));
  attackUDP(onoff3, c, 4);

  OnOffHelper onoff4 ("ns3::UdpSocketFactory", InetSocketAddress (i345.GetAddress (2), port));
  attackUDP(onoff4, c, 5);

  OnOffHelper onoff5 ("ns3::UdpSocketFactory", InetSocketAddress (i345.GetAddress (2), port));
  attackUDP(onoff5, c, 6);  

  OnOffHelper onoff6 ("ns3::UdpSocketFactory", InetSocketAddress (i345.GetAddress (2), port));
  attackUDP(onoff6, c, 7);

  OnOffHelper onoff7 ("ns3::UdpSocketFactory", InetSocketAddress (i345.GetAddress (2), port));
  attackUDP(onoff7, c, 9);

  OnOffHelper onoff8 ("ns3::UdpSocketFactory", InetSocketAddress (i345.GetAddress (2), port));
  attackUDP(onoff8, c, 10);

  OnOffHelper onoff9 ("ns3::UdpSocketFactory", InetSocketAddress (i345.GetAddress (2), port));
  attackUDP(onoff9, c, 11);

  OnOffHelper onoff10 ("ns3::UdpSocketFactory", InetSocketAddress (i345.GetAddress (2), port));
  attackUDP(onoff10, c, 12);

  OnOffHelper onoff11 ("ns3::UdpSocketFactory", InetSocketAddress (i345.GetAddress (2), port));
  attackUDP(onoff11, c, 13);

  OnOffHelper onoff12 ("ns3::UdpSocketFactory", InetSocketAddress (i345.GetAddress (2), port));
  attackUDP(onoff12, c, 14);  

  OnOffHelper onoff13 ("ns3::UdpSocketFactory", InetSocketAddress (i345.GetAddress (2), port));
  attackUDP(onoff13, c, 15);


 // define Flow Monitor


//Configure TAP on router
  TapBridgeHelper tapBridge;
  tapBridge.SetAttribute ("Mode", StringValue ("UseLocal"));
  tapBridge.SetAttribute ("DeviceName", StringValue ("tap0"));
  tapBridge.Install (c.Get (22), d345.Get(1));


  // Compose tracing helpers
  // define PCAP device tracing
  p2p.EnablePcap ("NS3MODEL_router0", d2d3.Get (0), false, false);
  p2p.EnablePcap ("NS3MODEL_router1", d2d3.Get (1), false, false);
  p2p.EnablePcapAll("tcplow");
  // define ASCII device tracing
  p2p.EnableAscii ("NS3MODEL_router0", d2d3.Get (0), false);
  p2p.EnableAscii ("NS3MODEL_router1", d2d3.Get (1), false);
  // define PCAP IPv4 interface tracing
  internet.EnablePcapIpv4 ("NS3MODEL_ipv4Interface0", i2i3);
  // define ASCII IPv4 interface tracing
  internet.EnableAsciiIpv4 ("NS3MODEL_ipv4Interface0", i2i3);

  Ptr<FlowMonitor> flowmon;
  FlowMonitorHelper flowmonHelper;
  flowmon = flowmonHelper.InstallAll ();
 
  Simulator::Stop (Seconds (30.0));
  Simulator::Run ();

  flowmon->CheckForLostPackets (); 
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier ()); 
  std::map<FlowId, FlowMonitor::FlowStats> stats = flowmon->GetFlowStats (); 
  double Throughput=0.0;

  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i =stats.begin (); i != stats.end (); ++i)
    {
      Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
      std::cout << "Flow " << i->first - 2 << " (" << t.sourceAddress<< " -> " << t.destinationAddress << ")\n";             
      std::cout <<"Tx Bytes:   " << i->second.txBytes << "\n";
      std::cout << "  Rx Bytes:   " << i->second.rxBytes << "\n";
      std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / 8.0 /1024 / 1024  << " Mbps\n";
      std::cout << "  Tx Packets:   " << i->second.txPackets << "\n";
      std::cout << "  Rx Packets:   " << i->second.rxPackets << "\n";
      std::cout << "  Delay Sum:   " << i->second.delaySum << "\n";
      std::cout << "  Average Delay:   " << i->second.delaySum / i->second.rxPackets<< "\n";
      Throughput=i->second.rxBytes * 8.0/(i->second.timeLastRxPacket.GetSeconds()-i->second.timeFirstTxPacket.GetSeconds())/1024;
      dataset.Add((double)i->first,(double) Throughput);
    } 

  // define Flow Monitor output file
  flowmonHelper.SerializeToXmlFile ("results.xml", true, true);

  gnuplot.AddDataset (dataset);
  std::ofstream plotFile (plotFileName.c_str());
  gnuplot.GenerateOutput (plotFile);
  plotFile.close ();

  Simulator::Destroy ();
  return 0;
}


