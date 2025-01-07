---
stand_alone: true
ipr: trust200902
cat: info # Check
submissiontype: IETF
area: General [REPLACE]
wg: Internet Engineering Task Force

docname: draft-ietf-savnet-inter-domain-problem-statement-07

title: Source Address Validation in Inter-domain Networks Gap Analysis, Problem Statement, and Requirements
abbrev: Inter-domain SAVNET Problem Statement
lang: en

author:
- ins: D. Li
  name: Dan Li
  org: Tsinghua University
  city: Beijing
  country: China
  email: tolidan@tsinghua.edu.cn
- ins: J. Wu
  name: Jianping Wu
  org: Tsinghua University
  city: Beijing
  country: China
  email: jianping@cernet.edu.cn
- ins: L. Liu
  name: Libin Liu
  org: Zhongguancun Laboratory
  city: Beijing
  country: China
  email: liulb@zgclab.edu.cn
- ins: M. Huang
  name: Mingqing Huang
  org: Zhongguancun Laboratory
  city: Beijing
  country: China
  email: huangmq@mail.zgclab.edu.cn
- ins: K. Sriram
  name: Kotikalapudi Sriram
  org: USA National Institute of Standards and Technology
  abbrev: USA NIST
  city: Gaithersburg
  region: MD
  country: United States of America
  email: ksriram@nist.gov

normative:
  RFC8174:
  RFC2119:
  RFC3704:
  RFC8704:
  RFC2827:
  RFC5210:
  RFC4364:
  RFC5635:
  RFC6811:
  RFC4786:
  RFC7094:
informative:
  intra-domain-ps:
    target: https://datatracker.ietf.org/doc/draft-ietf-savnet-intra-domain-problem-statement/
    title: Source Address Validation in Intra-domain Networks Gap Analysis, Problem Statement, and Requirements
    date: 2025
  manrs:
    target: https://www.manrs.org/netops/guide/antispoofing/
    title: MANRS Implementation Guide
    author:
     - org: MANRS
    date: 2023
  isoc:
    target: https://www.internetsociety.org/resources/doc/2015/addressing-the-challenge-of-ip-spoofing/
    title: Addressing the challenge of IP spoofing
    author:
     - org: Internet Society
    date: 2015
  nist:
    target: https://www.nist.gov/publications/resilient-interdomain-traffic-exchange-bgp-security-and-ddos-mitigation
    title: "Resilient Interdomain Traffic Exchange: BGP Security and DDos Mitigation"
    author:
     - org: NIST
    date: 2019
  urpf:
    target: https://www.cisco.com/c/dam/en_us/about/security/intelligence/urpf.pdf
    title: "Unicast Reverse Path Forwarding Enhancements for the Internet Service Provider-Internet Service Provider Network Edge"
    author:
     - org: Cisco Systems, Inc.
    date: 2005
  bar-sav:
    target: https://datatracker.ietf.org/doc/draft-ietf-sidrops-bar-sav/
    title: "Source Address Validation Using BGP UPDATEs, ASPA, and ROA (BAR-SAV)"
    author:
     - org: NIST, Akamai
    date: 2024


--- abstract

This document provides the gap analysis of existing inter-domain source address validation mechanisms, describes the fundamental problems, and defines the requirements for technical improvements.

--- middle

# Introduction

Source address validation (SAV) is crucial for protecting networks from source address spoofing attacks. The MANRS initiative advocates deploying SAV as close to the source as possible {{manrs}}, and access networks are the first line of defense against source address spoofing. However, access networks face various challenges in deploying SAV mechanisms due to different network environments, router vendors, and operational preferences. Hence, it is not feasible to deploy SAV at every network edge. Additional SAV mechanisms are needed at other levels of the network to prevent source address spoofing along the forwarding paths of the spoofing packets. The Source Address Validation Architecture (SAVA) {{RFC5210}} proposes a multi-fence approach that implements SAV at three levels of the network: access, intra-domain, and inter-domain.

If a spoofing packet is not blocked at the originating access network, intra-domain and inter-domain SAV mechanisms can help block the packet along its forwarding path. As analyzed in {{intra-domain-ps}}, intra-domain SAV for an AS can prevent a subnet of the AS from spoofing the addresses of other subnets as well as prevent incoming traffic to the AS from spoofing the addresses of the AS, without relying on the collaboration of other ASes. As complementary, in scenarios where intra-domain SAV cannot work, inter-domain SAV leverages the collaboration among ASes to help block incoming spoofing packets in an AS which spoof the source addresses of other ASes. It is noteworthy that scenarios where intra-domain SAV cannot work may consist of three cases: (1) the AS whose prefixes are being spoofed does not have intra-domain SAV deployed, (2) an AS requires the ASes near the spoofing attack source to filter the spoofing traffic, and (3) an AS whose source prefixes are spoofed may not be in the path of the spoofing traffic.

This document provides an analysis of inter-domain SAV. {{exp-inter-sav}} illustrates an example for inter-domain SAV. P1 is the source prefix of AS 1, and AS 4 sends spoofing packets with P1 as source addresses to AS 3 through AS 2. Assume AS 4 does not deploy intra-domain SAV, these spoofing packets cannot be blocked by AS 4. Although AS 1 can deploy intra-domain SAV to block incoming packets which spoof the addresses of AS 1, these spoofing traffic from AS 4 to AS 3 do not go through AS 1, so they cannot be blocked by AS 1. Inter-domain SAV can help in this scenario. If AS 1 and AS 2 deploy inter-domain SAV, AS 2 knows the correct incoming interface of packets with P1 as source addresses, and the spoofing packets can thus be blocked by AS 2 since they come from the incorrect interface.

~~~~~~~~~~
+------------+
|  AS 1(P1)  #
+------------+ \
                \            Spoofing Packets
              +-+#+--------+ with Source Addresses in P1 +------------+
              |    AS 2    #-----------------------------#    AS 4    |
              +-+#+--------+                             +------------+
                / 
+------------+ /
|    AS 3    #
+------------+
AS 4 sends spoofing packets with source addresses in P1 to AS 3 
through AS 2.
If AS 1 and AS 2 deploy inter-domain SAV, the spoofing packets 
can be blocked at AS 2.
~~~~~~~~~~
{: #exp-inter-sav title="An example for illustrating inter-domain SAV."}

There are many existing mechanisms for inter-domain SAV. This document analyzes them and attempts to answer: i) what are the technical gaps ({{gap}}), ii) what are the fundamental problems ({{problem}}), and iii) what are the practical requirements for the solution of these problems ({{req}}). 

## Requirements Language

{::boilerplate bcp14-tagged}

# Terminology

{:vspace}
SAV Rule:
: The rule that indicates the validity of a specific source IP address or source IP prefix.

Improper Block: 
: The validation results that the packets with legitimate source addresses are blocked improperly due to inaccurate SAV rules.

Improper Permit: 
: The validation results that the packets with spoofed source addresses  are permitted improperly due to inaccurate SAV rules.

Real forwading paths: 
: The paths that the legitimate traffic goes through in the data plane. 


# Existing Inter-domain SAV Mechanisms

Inter-domain SAV is typically performed at the AS level and can be deployed at AS border routers (ASBRs) to prevent source address spoofing. There are various mechanisms available to implement inter-domain SAV for anti-spoofing ingress filtering {{manrs}} {{isoc}}, which are reviewed in this section.

* ACL-based ingress filtering {{RFC2827}} {{RFC3704}}: ACL-based ingress filtering is a technique that relies on ACL rules to filter packets based on their source addresses. It can be applied at provider interfaces, peer interfaces, or customer interfaces of an AS, and is recommended to deploy at provider interfaces or customer interfaces {{manrs}} {{nist}}. At the provider interfaces, ACL-based ingress filtering can block source prefixes that are clearly invalid in the inter-domain routing context, such as suballocated or internal-only prefixes of customer ASes {{nist}}. At the customer interfaces, ACL-based ingress filtering can prevent customer ASes from spoofing source addresses of other ASes that are not reachable via the provider AS. It can be implemented at border routers or aggregation routers if border ACLs are not feasible {{manrs}}. However, ACL-based ingress filtering introduces significant operational overhead, as ACL rules need to be updated in a timely manner to reflect prefix or routing changes in the inter-domain routing system, which requires manual configuration to avoid improper block or improper permit.
* uRPF-based machanisms: A class of SAV mechanisms are based on Unicast Reverse Path Forwarding (uRPF) {{RFC3704}}. The core idea of uRPF for SAV is to exploit the symmetry of inter-domain routing: in many cases, the best next hop for a destination is also the best previous hop for the source. In other words, if a packet arrives from a certain interface, the source address of that packet should be reachable via the same interface, according to the FIB. However, symmetry in routing does not always holds in practice, and to address cases where it does not hold, many enhancements and modes of uRPF are proposed. Different modes of uRPF have different levels of strictness and flexibility, and network operators can choose from them to suit particular network scenarios. We describe these modes as follows:
  * Strict uRPF {{RFC3704}}: Strict uRPF is the most stringent mode, and it only permits packets that have a source address that is covered by a prefix in the FIB, and that the next hop for that prefix is the same as the incoming interface. This mode is recommended for deployment at customer interfaces that directly connect to an AS with suballocated address space, as it can prevent spoofing attacks from that AS or its downstream ASes {{nist}}.
  * Loose uRPF {{RFC3704}}: Loose uRPF verifies that the source address of the packet is routable in the Internet by matching it with one or more prefixes in the FIB, regardless of which interface the packet arrives at. If the source address is not routable, Loose uRPF discards the packet. Loose uRPF is typically deployed at the provider interfaces of an AS to block packets with source addresses that are obviously disallowed, such as non-global prefixes (e.g., private addresses, multicast addresses, etc.) or the prefixes that belong to the customer AS itself {{nist}}.
  * FP-uRPF {{RFC3704}}: FP-uRPF maintains a reverse path forwarding (RPF) list, which contains the prefixes and all their permissible routes including the optimal and alternative ones. It permits an incoming packet only if the packet's source address is encompassed in the prefixes of the RPF list and its incoming interface is included in the permissible routes of the corresponding prefix. FP-uRPF is recommended to be deployed at customer interfaces or peer interfaces, especially those that are connected to multi-homed customer ASes {{nist}}.
  * Virtual routing and forwarding (VRF) uRPF {{RFC4364}} {{urpf}}: VRF uRPF uses a separate VRF table for each external BGP peer. A VRF table is a table that contains the prefixes and the routes that are advertised by a specific peer. VRF uRPF checks the source address of an incoming packet from an external BGP peer against the VRF table for that peer. If the source address matches one of the prefixes in the VRF table, VRF uRPF allows the packet to pass. Otherwise, it drops the packet. VRF uRPF can also be used as a way to implement BCP38 {{RFC2827}}, which is a set of recommendations to prevent IP spoofing. However, the operational feasibility of VRF uRPF as BCP38 has not been proven {{manrs}}.
  * EFP-uRPF {{RFC8704}}: EFP-uRPF consists of two algorithms, algorithm A and algorithm B. EFP-uRPF is based on the idea that an AS can receive BGP updates for multiple prefixes that have the same origin AS at different interfaces. For example, this can happen when the origin AS is multi-homed and advertises the same prefixes to different providers. In this case, EFP-uRPF allows an incoming packet with a source address in any of those prefixes to pass on any of those interfaces. This way, EFP-uRPF can handle asymmetric routing scenarios where the incoming and outgoing interfaces for a packet are different. EFP-uRPF has not been implemented in practical networks yet, but BCP84 {{RFC3704}} {{RFC8704}} suggests using EFP-uRPF with algorithm B at customer interfaces of an AS. EFP-uRPF can also be used at peer interfaces of an AS.
* Source-based remote triggered black hole (RTBH) filtering {{RFC5635}}: Source-based RTBH filtering enables the targeted dropping of traffic by specifying particular source addresses or address ranges. Source-based RTBH filtering uses uRPF, usually Loose uRPF, to check the source address of an incoming packet against the FIB. If the source address of the packet does not match or is not covered by any prefix in the FIB, or if the route for that prefix points to a black hole (i.e., Null0), Loose uRPF discards the packet. This way, source-based RTBH filtering can filter out spoofing attack traffic at specific devices (e.g., ASBR) in an AS based on source addresses, and improve the security of the network.
* Carrier Grade NAT (CGN): CGN is a network technology used by service providers to translate between private and public IPv4 addresses within their network. CGN enables service providers to assign private IPv4 addresses to their customer ASes instead of public, globally unique IPv4 addresses. The private side of the CGN faces the customer ASes, and when an incoming packet is received from a customer AS, CGN checks its source address. If the source address is included in the address list of the CGN's private side, CGN performs address translation. Otherwise, it forwards the packet without translation. However, since CGN cannot determine whether the source address of an incoming packet is spoofed or not, additional SAV mechanisms need to be implemented to prevent source address spoofing {{manrs}}.
* BGP origin validation (BGP-OV) {{RFC6811}}: Attackers can bypass uRPF-based SAV mechanisms by using prefix hijacking in combination with source address spoofing. By announcing a less-specific prefix that does not have a legitimate announcement, the attacker can deceive existing uRPF-based SAV mechanisms and successfully perform address spoofing. To protect against this type of attack, a combination of BGP-OV and uRPF-based mechanisms like FP-uRPF or EFP-uRPF is recommended {{nist}}. BGP routers can use ROA information, which is a validated list of {prefix, maximum length, origin AS}, to mitigate the risk of prefix hijacks in advertised routes.

# Gap Analysis {#gap}

Inter-domain SAV is essential in preventing source address spoofing traffic across all AS interfaces, including those of customers, providers, and peers. An ideal inter-domain SAV mechanism MUST block all spoofing traffic while permitting legitimate traffic in all scenarios. However, in some cases, existing SAV mechanisms may unintentionally block legitimate traffic or permit spoofing traffic. This section aims to conduct a gap analysis of existing SAV mechanisms used in the corresponding interfaces of these scenarios to identify their technical limitations.

## SAV at Customer Interfaces

SAV is used at customer interfaces to validate traffic from the customer cone, including both legitimate traffic and spoofing traffic. To prevent the source address spoofing, operators can enable ACL-based ingress filtering, source-based RTBH filtering, and/or uRPF-based mechanisms at customer interfaces, namely Strict uRPF, FP-uRPF, VRF uRPF, or EFP-uRPF. However, uRPF-based mechanisms may cause improper block problems in two inter-domain scenarios: limited propagation of prefixes and hidden prefixes, or may cause improper permit problems in the scenarios of source address spoofing within a customer cone, while ACL-based ingress filtering and source-based RTBH filtering need to update SAV rules in a timely manner and lead to high operational overhead. For brevity, we will analyze ACL-based ingress filtering and source-based RTBH filtering in detail using the concrete cases in {{sav_at_p}}.

~~~~~~~~~~
+--------------------+------------+-----------+-------+--------+--------+
|Traffic & Scenarios |ACL & S/RTBH|Strict uRPF|FP-uRPF|VRF uRPF|EFP-uRPF|
+----------+---------+------------+-----------+-------+--------+--------+
|Legitimate|   LPP   |            |                                     |
|Traffic   +---------+            |            Improper Block           |
|          |   HP    |    High    |                                     |
+----------+---------+Operational +----------------------------+--------+
|Spoofing  |Spoofing |  Overhead  |                            |Improper|
|Traffic   | within  |            |   Functioning as Expected  |Permit  |
|          |  a CC   |            |                            |        |
+----------+---------+------------+----------------------------+--------+
S/RTBH: Source-based RTBH filtering.
"LPP" represents a class of scenario called limited propagation of 
prefixes. 
"HP" represents a calss of scenario called hidden prefixes.
"Spoofing within a CC" represents a class of scenario where 
spoofing traffic occurs within a customer cone (CC) and the spoofed 
source addresses belong to this customer cone.
"Functioning as Expected" represents the inter-domain SAV mechanism 
does not cause improper block for legitimate traffic or improper 
permit for spoofing traffic in the corresponding scenarios, and has 
low operational overhead.
~~~~~~~~~~
{: #customer_gap title="The gaps of ACL-based ingress filtering, source-based RTBH filtering, Strict uRPF, FP-uRPF, VRF uRPF, and EFP-uRPF in the corrresponding scenarios."}

{{customer_gap}} provides an overview of the gaps associated with ACL-based ingress filtering, source-based RTBH filtering, Strict uRPF, FP-uRPF, VRF uRPF, and EFP-uRPF for SAV at customer interfaces in the corresponding scenarios. Both ACL-based ingress filtering and source-based RTBH filtering have high operational overhead as performing SAV at customer interfaces. Strict uRPF, FP-uRPF, VRF uRPF, and EFP-uRPF, on the other hand, may incorrectly block legitimate traffic in the scenarios of limited propagation of prefixes or hidden prefixes. Furthermore, in the scenarios of source address spoofing within a customer cone, EFP-uRPF with algorithm B may inadvertently permit the spoofing traffic.

In the following, we analyze the gaps of Strict uRPF, FP-uRPF, VRF uRPF, and EFP-uRPF for SAV at customer interfaces in scenarios of limited propagation of prefixes, hidden prefixes, and source address spoofing within a customer cone, respectively.

### Limited Propagation of Prefixes

In inter-domain networks, some prefixes may not be propagated to all domains due to various factors, such as NO_EXPORT or NO_ADVERTISE communities or other route filtering policies. This may cause asymmetric routing in the inter-domain context, which may lead to improper block when performing SAV with existing mechanisms. These mechanisms include EFP-uRPF, which we focus on in the following analysis, as well as Strict uRPF, FP-uRPF, and VRF uRPF. All these mechanisms suffer from the same problem of improper block in this scenario.

~~~~~~~~~~
                          +----------------+
                          |    AS 3(P3)    |
                          +-+/\------+/\+--+
                             /         \
                            /           \ 
                           /             \
                          / (C2P)         \
                 +------------------+      \
                 |     AS 4(P4)     |       \
                 ++/\+--+/\+----+/\++        \
                   /     |        \           \
         P2[AS 2] /      |         \           \
                 /       |          \           \
                / (C2P)  |           \ P5[AS 5]  \ P5[AS 5]
+----------------+       |            \           \    
|    AS 2(P2)    |       | P1[AS 1]    \           \
+----------+/\+--+       | P6[AS 1]     \           \
             \           | NO_EXPORT     \           \
     P1[AS 1] \          |                \           \
     NO_EXPORT \         |                 \           \
                \ (C2P)  | (C2P/P2P)  (C2P) \     (C2P) \
              +----------------+          +----------------+
              |  AS 1(P1, P6)  |          |    AS 5(P5)    |
              +----------------+          +----------------+
~~~~~~~~~~
{: #no-export title="Limited propagation of prefixes caused by NO_EXPORT."} 

{{no-export}} presents a scenario where the limited propagation of prefixes occurs due to the NO_EXPORT community attribute. In this scenario, AS 1 is a customer of AS 2, AS 2 is a customer of AS 4, AS 4 is a customer of AS 3, and AS 5 is a customer of both AS 3 and AS 4. The relationship between AS 1 and AS 4 can be either customer-to-provider (C2P) or peer-to-peer (P2P). AS 1 advertises prefixes P1 to AS 2 and adds the NO_EXPORT community attribute to the BGP advertisement sent to AS 2, preventing AS 2 from further propagating the route for prefix P1 to AS 4. Similarly, AS 1 adds the NO_EXPORT community attribute to the BGP advertisement sent to AS 4, resulting in AS 4 not propagating the route for prefix P6 to AS 3. Consequently, AS 4 only learns the route for prefix P1 from AS 1 in this scenario. Suppose AS 1 and AS 4 have deployed inter-domain SAV while other ASes have not, and AS 4 has deployed EFP-uRPF at its customer interfaces. 

Assuming that AS 1 is the customer of AS 4, if AS 4 deploys EFP-uRPF with algorithm A at customer interfaces, it will require packets with source addresses in P1 to only arrive from AS 1. When AS 1 sends legitimate packets with source addresses in P1 to AS 4 through AS 2, AS 4 improperly blocks these packets. The same problem applies to Strict uRPF, FP-uRPF, and VRF uRPF. Although EFP-uRPF with algorithm B can avoid improper block in this case, network operators need to first determine whether limited prefix propagation exists before choosing the suitable EFP-uRPF algorithms, which adds more complexity and overhead to network operators. Furthermore, EFP-uRPF with algorithm B is not without its problems. For example, if AS 1 is the peer of AS 4, AS 4 will not learn the route of P1 from its customer interfaces. In such case, both EFP-uRPF with algorithm A and algorithm B have improper block problems.

### Hidden Prefixes

Some servers' source addresses are not advertised through BGP to other ASes. These addresses are unknown to the inter-domain routing system and are called hidden prefixes. Legitimate traffic with these hidden prefixes may be dropped by existing inter-domain SAV mechanisms, such as Strict uRPF, FP-uRPF, VRF uRPF, or EFP-uRPF, because they do not match any known prefix.

For example, Content Delivery Networks (CDN) use anycast {{RFC4786}} {{RFC7094}} to improve the quality of service by bringing content closer to users. An anycast IP address is assigned to devices in different locations, and incoming requests are routed to the closest location. Usually, only locations with multiple connectivity announce the anycast IP address through BGP. The CDN server receives requests from users and creates tunnels to the edge locations, where content is sent directly to users using direct server return (DSR). DSR requires servers in the edge locations to use the anycast IP address as the source address in response packets. However, these edge locations do not announce the anycast prefixes through BGP, so an intermediate AS with existing inter-domain SAV mechanisms may improperly block these response packets.

~~~~~~~~~~
                                +----------------+
                Anycast Server+-+    AS 3(P3)    |
                                +-+/\----+/\+----+
                                   /       \
                         P3[AS 3] /         \ P3[AS 3]
                                 /           \
                                / (C2P)       \
                       +----------------+      \
                       |    AS 4(P4)    |       \
                       ++/\+--+/\+--+/\++        \
          P6[AS 1, AS 2] /     |      \           \
               P2[AS 2] /      |       \           \
                       /       |        \           \
                      / (C2P)  |         \ P5[AS 5]  \ P5[AS 5]
      +----------------+       |          \           \    
User+-+    AS 2(P2)    |       | P1[AS 1]  \           \
      +----------+/\+--+       | P6[AS 1]   \           \
          P6[AS 1] \           | NO_EXPORT   \           \
           P1[AS 1] \          |              \           \
           NO_EXPORT \         |               \           \
                      \ (C2P)  | (C2P)    (C2P) \     (C2P) \
                    +----------------+        +----------------+
       Edge Server+-+  AS 1(P1, P6)  |        |    AS 5(P5)    |
                    +----------------+        +----------------+
P3 is the anycast prefix and is only advertised by AS 3 through BGP.
~~~~~~~~~~
{: #dsr title="A Direct Server Return (DSR) scenario."}

{{dsr}} illustrates a DSR scenario where the anycast IP prefix P3 is only advertised by AS 3 through BGP. In this example, AS 3 is the provider of AS 4 and AS 5, AS 4 is the provider of AS 1, AS 2, and AS 5, and AS 2 is the provider of AS 1. AS 1 and AS 4 have deployed inter-domain SAV, while other ASes have not. When users in AS 2 send requests to the anycast destination IP, the forwarding path is AS 2->AS 4->AS 3. The anycast servers in AS 3 receive the requests and tunnel them to the edge servers in AS 1. Finally, the edge servers send the content to the users with source addresses in prefix P3. The reverse forwarding path is AS 1->AS 4->AS 2. Since AS 4 does not receive routing information for prefix P3 from AS 1, EFP-uRPF with algorithm A/B, and all other existing uRPF-based mechanisms at the customer interface of AS 4 facing AS 1 will improperly block the legitimate response packets from AS 1.

Moreover, it is worth mentioning that EFP-uRPF with algorithm B may also permit spoofing traffic improperly in scenarios where source address spoofing within a customer cone occur. We provide illustrations of these scenarios using an example in the following. The source address spoofing within a customer cone represents a class of scenario where spoofing traffic comes from a customer AS within a customer cone and the spoofed source addresses belong to this customer cone.

### Source Address Spoofing within a Customer Cone {#spoofing_within_cc}

{{customer-spoofing}} portrays a scenario of source address spoofing within a customer cone and is used to analyze the gaps of uRPF-based mechanisms below. 

~~~~~~~~~~
                                       +----------------+
                                       |    AS 3(P3)    |
                                       +-+/\----+/\+----+
                                          /       \
                                         /         \ 
                                        /           \
                                       / (C2P)       \
                              +----------------+      \
                              |    AS 4(P4)    |       \
                              ++/\+--+/\+--+/\++        \
                 P6[AS 1, AS 2] /     |      \           \
                P1[AS 1, AS 2] /      |       \           \
                     P2[AS 2] /       |        \           \
                             / (C2P)  |         \ P5[AS 5]  \ P5[AS 5]
             +----------------+       |          \           \    
Spoofer(P5')-+    AS 2(P2)    |       | P1[AS 1]  \           \
             +----------+/\+--+       | P6[AS 1]   \           \
                          \           |             \           \
                  P6[AS 1] \          |              \           \
                   P1[AS 1] \         |               \           \
                             \ (C2P)  | (C2P)    (C2P) \     (C2P) \
                           +----------------+        +----------------+
                           |  AS 1(P1, P6)  |        |    AS 5(P5)    |
                           +----------------+        +----------------+
P5' is the spoofed source prefix P5 by the spoofer which is inside of 
AS 2 or connected to AS 2 through other ASes.
~~~~~~~~~~
{: #customer-spoofing title="A scenario of source address spoofing within a customer cone."}

In {{customer-spoofing}}, the source address spoofing takes place within AS 4's customer cone, where the spoofer, which is inside of AS 2 or connected to AS 2 through other ASes, sends spoofing traffic with spoofed source addresses in P5 to AS 3 along the path AS 2->AS 4-> AS 3. The arrows in {{customer-spoofing}} illustrate the commercial relationships between ASes. AS 3 serves as the provider for AS 4 and AS 5, while AS 4 acts as the provider for AS 1, AS 2, and AS 5. Additionally, AS 2 is the provider for AS 1. Suppose AS 1 and AS 4 have deployed inter-domain SAV, while the other ASes have not.

If AS 4 deploys EFP-uRPF with algorithm B at its customer interfaces, it will allow packets with source addresses in P5 to originate from AS 1, AS 2, and AS 5. Consequently, when the spoofer sends spoofing packets with spoofed source addresses in P5 to AS 3, AS 4 will improperly permit these packets, thus enabling the spoofing traffic to propagate.

In scenarios like these, Strict uRPF, FP-uRPF, VRF uRPF, and EFP-uRPF with algorithm A do not suffer from improper permit problems. This is because these mechanisms enforce strict filtering rules that ensure packets with source addresses in P5 are only permitted to arrive at AS 4's customer interfaces facing AS 5.

## SAV at Provider/Peer Interfaces {#sav_at_p}

SAV is used at provider/peer interfaces to validate traffic entering the customer cone, including both legitimate and spoofing traffic. To prevent packets with spoofed source addresses from the provider/peer AS, ACL-based ingress filtering and/or Loose uRPF can be deployed {{nist}}. In addition, source-based RTBH filtering can be used to remotely configure SAV rules.

~~~~~~~~~~
+------------------------+------------+---------------+
|   Traffic & Scenarios  |ACL & S/RTBH|   Loose uRPF  |
+----------+-------------+------------+---------------+
|Legitimate|      Any    |            |  Functioning  |
|Traffic   |  Scenarios  |    High    |  as Expected  |
+----------+-------------+Operational +---------------+
|Spoofing  |   Spoofing  |  Overhead  |               |
|Traffic   |     from    |            |Improper Permit|
|          |Provider/Peer|            |               |
|          |      AS     |            |               |
+----------+-------------+------------+---------------+
S/RTBH: Source-based RTBH filtering.
"Spoofing from provider/peer AS" represents a class of scenario where 
source address spoofing traffic from provider/peer AS occurs and the 
spoofed source addresses belong to the customer cone which the 
spoofing traffic enters.
"Functioning as Expected" represents the inter-domain SAV mechanism 
does not cause improper block for legitimate traffic or improper 
permit for spoofing traffic in the corresponding scenarios, and has 
low operational overhead.
~~~~~~~~~~
{: #provider_peer_gap title="The gaps of ACL-based ingress filtering, source-based RTBH filtering, and Loose uRPF in the corresponding scenarios."}

{{provider_peer_gap}} summarizes the gaps of ACL-based ingress filtering, source-based RTBH filtering, and Loose uRPF for SAV at provider/peer interfaces in the corresponding scenarios. ACL-based ingress filtering and source-based RTBH filtering effectively block spoofing traffic from provider/peer AS, while appropriately allowing legitimate traffic. However, these methods may come with high operational overhead. On the other hand, Loose uRPF correctly permits legitimate traffic, but it can also mistakenly allow spoofing traffic to pass through.

In the following, we expose the limitations of ACL-based ingress filtering, source-based RTBH filtering, and Loose uRPF for SAV at provider/peer interfaces in scenarios of source address spoofing from provider/peer AS. The source address spoofing from provider/peer AS represents a class of scenario where spoofing traffic comes from a provider/peer AS and the spoofed source addresses belong to the customer cone which the spoofing traffic enters.

### Source Address Spoofing from Provider/Peer AS

{{provider-spoofing}} depicts the scenario of source address spoofing from provider/peer AS and is used to analyze the gaps of ACL-based ingress filtering, source-based RTBH filtering, and Loose uRPF below.

~~~~~~~~~~
                          +----------------+
            Spoofer(P1')+-+    AS 3(P3)    |
                          +-+/\----+/\+----+
                             /       \
                            /         \ 
                           /           \
                          / (C2P/P2P)   \
                 +----------------+      \
                 |    AS 4(P4)    |       \
                 ++/\+--+/\+--+/\++        \
    P6[AS 1, AS 2] /     |      \           \
   P1[AS 1, AS 2] /      |       \           \
        P2[AS 2] /       |        \           \
                / (C2P)  |         \ P5[AS 5]  \ P5[AS 5]
+----------------+       |          \           \    
|    AS 2(P2)    |       | P1[AS 1]  \           \
+----------+/\+--+       | P6[AS 1]   \           \
             \           |             \           \
     P6[AS 1] \          |              \           \
      P1[AS 1] \         |               \           \
                \ (C2P)  | (C2P)    (C2P) \     (C2P) \
               +----------------+        +----------------+
               |  AS 1(P1, P6)  |        |    AS 5(P5)    |
               +----------------+        +----------------+
P1' is the spoofed source prefix P1 by the spoofer which is inside of 
AS 3 or connected to AS 3 through other ASes.
~~~~~~~~~~
{: #provider-spoofing title="A scenario of source address spoofing from provider/peer AS."}

In the case of {{provider-spoofing}}, the spoofer forges the source addresses in P1 and sends the spoofing traffic to the destination addresses in P2. The arrows in {{provider-spoofing}} represent the commercial relationships between ASes. AS 3 acts as the provider or lateral peer of AS 4 and the provider for AS 5, while AS 4 serves as the provider for AS 1, AS 2, and AS 5. Additionally, AS 2 is the provider for AS 1. Suppose AS 1 and AS 4 have deployed inter-domain SAV, while the other ASes have not.

By applying ACL-based ingress filtering at the provider/peer interface of AS 4, the ACL rules can block any packets with spoofed source addresses from AS 3 in P1. However, this approach incurs heavy operational overhead, as it requires network operators to update the ACL rules promptly based on changes in prefixes or topology of AS 4's customer cone. Otherwise, it may cause improper block of legitimate traffic or improper permit of spoofing traffic.

Source-based RTBH filtering allows for the deployment of SAV rules on AS 1 and AS 4 remotely. However, in order to avoid improper block or improper permit, the specified source addresses need to be updated in a timely manner, which incurs additional operational overhead.

Loose uRPF can greatly reduce the operational overhead because it uses the local FIB as information source, and can adapt to changes in the network. However, it would improperly permit spoofed packets. In {{provider-spoofing}}, Loose uRPF is enabled at AS 4's provider/peer interface, while EFP-uRPF is enabled at AS 4's customer interfaces. A spoofer inside AS 3 or connected to it through other ASes may send packets with source addresses spoofing P1 to AS 2. As AS 3 lacks deployment of inter-domain SAV, the spoofing packets will reach AS 4's provider/peer interface. With Loose uRPF, AS 4 cannot block them at its provider/peer interface facing AS 3, and thus resulting in improper permit.

# Problem Statement {#problem}

~~~~~~~~~~
+--------+----------+---------+----------+-------+--------+----------+
|Problems|    ACL   |  Strict |  Loose   |FP-uRPF|VRF uRPF|EFP-uRPF  |
|        | & S/RTBH |  uRPF   |  uRPF    |       |        |          |
+--------+----------+---------+----------+-------+--------+----------+
|Improper|Not Exist |  Exist  |Not Exist |           Exist           |
|Block   |          |(LPP, HP)|          |         (LPP, HP)         |
+--------+----------+---------+----------+----------------+----------+
|Improper|      Not Exist     |  Exist   |    Not Exist   |  Exist   |
|Permit  |                    |  (SPP)   |                |  (SCC)   |
+--------+----------+---------+----------+----------------+----------+
|        |   Exist  |                                                |
|  HOO   |   (Any   |                    Not Exist                   |
|        |Scenarios)|                                                |
+--------+----------+------------------------------------------------+
S/RTBH: Source-based RTBH filtering, HOO: High Operational Overhead.
"LPP" represents a class of scenario called limited propagation of 
prefixes. 
"HP" represents a class of scenario called hidden prefixes.
"SPP" represents a class of scenario called source address spoofing 
from provider/peer AS. 
"SCC" represents a class of scenario called source address spoofing 
within a customer cone.
~~~~~~~~~~
{: #problem_sum title="The scenarios where existing inter-domain SAV mechanisms may have improper block problem for legitimate traffic, improper permit problem for spoofing traffic, or high operational overhead."}

Based on the analysis above, we conclude that existing inter-domain SAV mechanisms exhibit limitations in asymmetric routing scenarios, leading to potential issues of improper block or improper permit. Additionally, these mechanisms can result in high operational overhead, especially when network routing undergoes dynamic changes. {{problem_sum}} provides a comprehensive summary of scenarios where existing inter-domain SAV mechanisms may encounter issues, including instances of improper blocking of legitimate traffic, improper permitting of spoofing traffic, or high operational overhead.

For ACL-based ingress filtering, network operators need to manually update ACL rules to adapt to network changes. Otherwise, they may cause improper block or improper permit issues. Manual updates induce high operational overhead, especially in networks with frequent policy and route changes. Source-based RTBH filtering has the similar problem as ACL-based ingress filtering.

Strict uRPF and Loose uRPF are automatic SAV mechanisms, thus they do not need any manual effort to adapt to network changes. However, they have issues in scenarios with asymmetric routing. Strict uRPF may cause improper block problems when an AS is multi-homed and routes are not symmetrically announced to all its providers. This is because the local FIB may not include the asymmetric routes of the legitimate packets, and Strict uRPF only uses the local FIB to check the source addresses and incoming interfaces of packets. Loose uRPF may cause improper permit problems and fail to prevent source address spoofing. This is because it is oblivious to the incoming interfaces of packets.

FP-uRPF and VRF uRPF improve Strict uRPF in multi-homing scenarios. However, they still have improper block issues in asymmetric routing scenarios. For example, they may not handle the cases of limited propagation of prefixes. These mechanisms use the local RIB to learn the source prefixes and their valid incoming interfaces. But the RIB may not have all the prefixes with limited propagation and their permissible incoming interfaces.

EFP-uRPF allows the prefixes from the same customer cone at all customer interfaces. This solves the improper block problems of FP-uRPF and VRF uRPF in multi-homing scenarios. However, this approach also compromises partial protection against spoofing from the customer cone. EFP-uRPF may still have improper block problems when it does not learn legitimate source prefixes. For example, hidden prefixes are not learned by EFP-uRPF. 

Finally, existing inter-domain SAV mechanisms cannot work in all directions (i.e. interfaces) of ASes to achieve effective SAV. Network operators need to carefully analyze the network environment and choose approapriate SAV mechansim for each interface. This leads to additional operational and cognitive overhead, which hinders the rate of adoption of inter-domain SAV.

# Requirements for New Inter-domain SAV Mechanisms {#req}

This section lists the requirements which can help bridge the technical gaps of existing inter-domain SAV mechanisms. These requirements serve as the practical guidelines that can be met, in part or in full, by proposing new techniques.

## Accurate Validation

The new inter-domain SAV mechanism MUST improve the validation accuracy in all directions of ASes over existing inter-domain SAV mechanisms, while working in incremental/partial deployment and providing necessary security guarantee. 

### Improving Validation Accuracy over Existing Mechanisms

It MUST avoid improper block and permit less spoofing traffic than existing inter-domain SAV mechanisms. To avoid improper block, ASes that deploy the new inter-domain SAV mechanism SHOULD be able to acquire all the real data plane forwarding paths, which are the paths that the legitimate traffic goes through in the data plane.

However, it may be hard to learn the real forwarding paths of prefixes exactly under some scenarios, such as asymmetric routing scenario and DSR scenario. For such scenarios, it is crucial to minimize the set of acceptable paths while ensuring the inclusion of all real forwarding paths, thereby preventing improper block and minimizing improper permit. Note that the acceptable paths are all the possible paths that the legitimate traffic may go through in the data plane, cover all the links at each level of customer-provider hierarchy, and MUST include all the real forwarding paths. Reducing the set of acceptable paths means eliminating the paths that are not the real forwarding paths of the prefixes from the set. 

~~~~~~~~~~
                          +----------------+
                          |    AS 3(P3)    |
                          +-+/\----+/\+----+
                             /       \
                            /         \ 
                           /           \
                          / (C2P)       \
                 +----------------+      \
                 |    AS 4(P4)    |       \
                 ++/\+--+/\+--+/\++        \
    P6[AS 1, AS 2] /     |      \           \
         P2[AS 2] /      |       \           \
                 /       |        \           \
                / (C2P)  |         \ P5[AS 5]  \ P5[AS 5]
+----------------+       |          \           \    
|    AS 2(P2)    |       | P1[AS 1]  \           \
+----------+/\+--+       | P6[AS 1]   \           \
    P6[AS 1] \           | NO_EXPORT   \           \
     P1[AS 1] \          |              \           \
     NO_EXPORT \         |               \           \
                \ (C2P)  | (C2P)    (C2P) \     (C2P) \
              +----------------+        +----------------+
              |  AS 1(P1, P6)  |        |    AS 5(P5)    |
              +----------------+        +----------------+
~~~~~~~~~~
{: #accurate_validation title="An example to illustrate accurate validation in all directions of an AS."}

Multiple sources of SAV-related information, such as RPKI ROA objects and ASPA objects, and SAV-specific information from other ASes, can assist in reducing the set of acceptable paths. {{accurate_validation}} is used as an example to illustrate how to avoid improper block and minimize improper permit in all directions of an AS based on different SAV information sources. AS 3 is the provider of AS 4 and AS 5, while AS 4 is the provider of AS 1, AS 2, and AS 5, and AS 2 is the provider of AS 1. Assuming prefixes P1, P2, P3, P4, P5, and P6 are all the prefixes in the network. Inter-domain SAV has been deployed by AS 1 and AS 4, but not by other ASes. Here, the focus is on how to conduct SAV in all directions of AS 4 when different SAV information sources are available to use. 

Since the source prefix ranges of the traffic entering the customer cone of AS 4 are not fully learned in the partial deployment scenario, SAV at provider/peer interfaces can use a blocklist. For example, as shown in {{accurate_validation}}, the traffic with source addresses in P5 may come from AS 5 or AS 3. In contrast, SAV at customer interfaces for traffic going out of the customer cone can use an allowlist to allow the known prefixes of the customer cone at the corresponding customer interfaces and other unknown prefixes at all the customer interfaces. 

The followings show how to generate SAV rules based on the SAV-related information from different SAV information sources to avoid improper block and reduce as much improper permit as possible. 

* If only the RIB is available, AS 4 can conduct SAV towards its neighboring ASes as follows like {{RFC8704}}: SAV towards AS 1 permits the prefixes P1 and P6, SAV towards AS 2 permits the prefixes P1, P2, and P6, SAV towards AS 5 permits the prefix P5, and SAV towards AS 3 does not block any prefix. 

* When both RPKI ROA objects and ASPA objects are deployed by AS 1 and AS 4, AS 4 can conduct SAV towards its neighboring ASes as follows like {{bar-sav}}: SAV towards AS 1 permits the prefixes P1 and P6, SAV towards AS 2 permits the prefixes P1, P2, and P6, SAV towards AS 5 permits the prefix P5, and SAV towards AS 3 blocks the prefixes P1, P2, and P6. 

* Moreover, if SAV-specific information that exactly contains all the real data plane forwarding paths of prefixes is accessible, SAV rules can be refined. AS 4 can conduct SAV towards its neighboring ASes as follows: SAV towards AS 1 permits only P1. SAV towards AS 2 permits the prefixes P2 and P6, while SAV towards AS 5 permits the prefix P5 and SAV towards AS 3 blocks the prefixes P1, P2, and P6.

It is evident that, in a partial deployment scenario, more accurate SAV-related information can effectively achieve 0% improper block and significantly minimize improper permit.

### Working in Incremental/Partial Deployment

The new inter-domain SAV mechanism MUST NOT assume pervasive adoption and SHOULD provide effective protection for source addresses when it is partially deployed in the Internet. Not all AS border routers can support the new SAV mechanism at once, due to various constraints such as capabilities, versions, or vendors. The new SAV mechanism should not be less effective in protecting all directions of ASes under partial deployment than existing mechanisms. 

### Providing Necessary Security Guarantee

The new inter-domain SAV mechanism SHOULD secure the communicated SAV-specific information between ASes and prevent malicious ASes from generating forged information.


## Automatic Update

The new inter-domain SAV mechanism SHOULD update SAV rules and detect the changes of SAV-specific information automatically while guaranteeing convergence.

### Reducing Operational Overhead

The new inter-domain SAV mechanism MUST be able to adapt to dynamic networks and asymmetric routing scenarios automatically, instead of relying on manual update. At least, it SHOULD have less operational overhead than ACL-based ingress filtering and Source-based RTBH filtering.

### Guaranteeing Convergence
The new inter-domain SAV mechanism SHOULD promptly detect the network changes and launch the convergence process quickly. It is essential that the new inter-domain SAV mechanism converges towards accurate SAV rules in a proper manner, effectively reducing improper block and improper permit throughout the whole convergence process.


# Inter-domain SAV Scope

The new inter-domain SAV mechanisms should work in the same scenarios as existing ones. Generally, it includes all IP-encapsulated scenarios:

* Native IP forwarding: This includes both global routing table forwarding and CE site forwarding of VPN.
* IP-encapsulated Tunnel (IPsec, GRE, SRv6, etc.): In this scenario, we focus on the validation of the outer layer IP address.
* Both IPv4 and IPv6 addresses.

Scope does not include:

* Non-IP packets: This includes MPLS label-based forwarding and other non-IP-based forwarding.

In addition, the new inter-domain SAV mechanisms should not modify data plane packets. Existing architectures or protocols or mechanisms can be inherited by the new SAV mechanism to achieve better SAV effectiveness.

# Security Considerations {#Security}

SAV rules can be generated based on route information (FIB/RIB) or non-route information. If the information is poisoned by attackers, the SAV rules will be false. Legitimate packets may be dropped improperly or malicious traffic with spoofed source addresses may be permitted improperly. Route security should be considered by routing protocols. Non-route information, such as RPKI ASPA objects, should also be protected by corresponding mechanisms or infrastructure. If SAV mechanisms or protocols require exchanging specific information between ASes, some considerations on the avoidance of message alteration or message injection are needed to propose.

The SAV procedure referred in this document modifies no field of packets. So, security considerations on the data plane are not in the scope of this document.

# IANA Considerations {#IANA}

This document does not request any IANA allocations.

# Contributors

Lancheng Qin  
  Zhongguancun Laboratory  
  Beijing,
  China   
  Email: qinlc@zgclab.edu.cn

Nan Geng  
  Huawei  
  Beijing,
  China   
  Email: gengnan@huawei.com

--- back

# Acknowledgements {#Acknowledgements}
{: numbered="false"}

Many thanks to Jared Mauch, Barry Greene, Fang Gao, Anthony Somerset, Yuanyuan Zhang, Igor Lubashev, Alvaro Retana, Joel Halpern, Aijun Wang, Michael Richardson, Li Chen, Gert Doering, Mingxing Liu, John O'Brien, Roland Dobbins, etc. for their valuable comments on this document.