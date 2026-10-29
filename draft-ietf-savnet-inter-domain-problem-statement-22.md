---
stand_alone: true
ipr: trust200902
cat: info
submissiontype: IETF
area: Routing
wg: SAVNET

docname: draft-ietf-savnet-inter-domain-problem-statement-22

title: Problem Statement, Gap Analysis, and Requirements for Inter-domain Source Address Validation 
abbrev: Inter-domain SAVNET Problem Statement
lang: en

author:
- ins: D. Li
  name: Dan Li
  org: Tsinghua University
  city: Beijing
  country: China
  email: tolidan@tsinghua.edu.cn
- ins: L. Qin
  name: Lancheng Qin
  org: Zhongguancun Laboratory
  city: Beijing
  country: China
  email: qinlc@zgclab.edu.cn
- ins: L. Liu
  name: Libin Liu
  org: Zhongguancun Laboratory
  city: Beijing
  country: China
  email: liulb@zgclab.edu.cn
- ins: M. Huang
  name: Mingqing Huang
  org: Huawei
  city: Beijing
  country: China
  email: huangmq@vip.sina.com
- ins: K. Sriram
  name: Kotikalapudi Sriram
  org: USA National Institute of Standards and Technology
  abbrev: USA NIST
  city: Gaithersburg
  region: MD
  country: United States of America
  email: sriram.ietf@gmail.com

normative:
  RFC2827:
  RFC4271:
  RFC5210:
  RFC3704:
  RFC8704:

informative:
  RFC1997:
  RFC6996:
  RFC7908:
  RFC9234:
  RFC7094:
  RFC4364:
  RFC4786:
  RFC8416:
  RFC7947: 
  RFC6811:
  RFC8205:
  I-D.ietf-savnet-intra-domain-problem-statement:
  I-D.ietf-opsawg-rfc5706bis:
  
  Cisco:
    target: https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/ip-routing/b-ip-routing/m_irg-remove-as-0.html 
    title: IP Routing Configuration Guide -- Chapter on Removing Private AS Numbers from the AS Path in BGP
    author:
     - org: Cisco publication
    date: Accessed 2026
  
  Juniper:
    target: https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/remove-private-edit-protocols-bgp.html 
    title: Junos CLI Reference (remove-private)
    author:
     - org: Juniper publication
    date: Accessed 2026
	
  manrs:
    target: https://manrs.org/resources/training/tutorials/anti-spoofing/
    title: Anti-Spoofing - Preventing traffic with spoofed source IP addresses (Module 5)
    author:
     - org: MANRS publication
    date: Accessed 2026

  isoc:
    target: https://www.internetsociety.org/resources/doc/2015/addressing-the-challenge-of-ip-spoofing/
    title: Addressing the challenge of IP spoofing
    author:
     - org: Internet Society publication
    date: 2015
  
  nist:
    target: https://doi.org/10.6028/NIST.SP.800-189r1.ipd
    title: "Border Gateway Protocol Security and Resilience"
    author:
    - ins: K. Sriram
      org: NIST
    - ins: D. Montgomery
      org: NIST
    date: 2025
    seriesinfo:
      "NIST SP": "800-189 Rev. 1 (Initial Public Draft)"

  urpf:
    target: https://www.cisco.com/c/dam/en_us/about/security/intelligence/urpf.pdf
    title: "Unicast Reverse Path Forwarding Enhancements for the Internet Service Provider-Internet Service Provider Network Edge"
    author:
     - org: Cisco Systems, Inc.
    date: 2005

  SAC-004:
    target: https://www.icann.org/en/ssac/publications/documents/sac-004-security-and-stability-advisory-committee-securing-the-edge-17-10-2002-en
    title: "SAC 004 | Security and Stability Advisory Committee - Securing the Edge"
    author:
    - ins: Paul Vixie
      org: ISC
    date: 2002

...

--- abstract

This document analyzes the problem space and provides a gap analysis of existing inter-domain source address validation (SAV) mechanisms. Based on these findings, it outlines the technical requirements for future improvements.

--- middle

# Introduction {#intro}

Source Address Validation (SAV) is a fundamental mechanism for detecting and mitigating source address spoofing attacks {{RFC2827}} {{RFC5210}} {{RFC3704}} {{RFC8704}}. Inter-domain SAV, defined in the context of Internet routing using BGP-4 {{RFC4271}}, checks the source addresses of data traffic received from a neighboring Autonomous System (AS), whether that traffic originated within the neighbor's network or is being transited through it. Inter-domain SAV is applied at border routers to incoming traffic on external interfaces directly connected to a neighboring AS. The local AS (the one performing SAV) and the neighbor AS are connected using external BGP (eBGP). The neighbor AS could be using either a public AS number (ASN) or a private ASN {{RFC6996}}.  

This document analyzes the problem space and provides a gap analysis of existing inter-domain SAV mechanisms. Based on these findings, it outlines the technical requirements for future improvements.
The corresponding work related to intra-domain SAV is documented in [I-D.ietf-savnet-intra-domain-problem-statement], which includes SAV for hosts and customers (non-AS) connected to the AS {{SAC-004}}.

The eBGP sessions between the border routers of the SAV performing AS and the neighbor ASes may include Customer-to-Provider (C2P), Provider-to-Customer (P2C), lateral peering (P2P), and Route Server (RS) to RS-client connection. The terms customer, provider (transit provider), and lateral peer (non-transit peer; peer (for simplicity)) used in this document are consistent with those defined in {{RFC7908}} {{RFC9234}}. 
Further, {{RFC9234}} mentions RS and RS-client. As described in {{RFC7947}}, a route server exchanges BGP routes among its clients without forwarding their data traffic. 
The traffic an RS-client receives at an IXP comes from the member ASes, often over one interface shared by route-server and bilateral peers. For the purposes of SAV, that interface may be treated (1) like a provider interface for simplicity, or (2) like a union of lateral peers considering all the ASes the RS-client exchanges routes with at the IXP, which requires distinguishing the member AS that sent each packet.

For the terminology used in this section and the rest of the document, see {{terminology}}.

Access Control List (ACL) and unicast Reverse Path Forwarding (uRPF) based techniques are currently utilized to some extent for inter-domain SAV. In this document, the inter-domain SAV methods from only the existing IETF RFCs (BCP 38 {{RFC2827}} and BCP 84 {{RFC3704}} {{RFC8704}}) are considered for the gap analysis.

This document analyzes the technical gaps of existing inter-domain SAV mechanisms in {{gap}} and summarizes them in {{problem}}. Based on this analysis, {{req}} identifies the requirements for new inter-domain SAV mechanisms to address these gaps.

Note that this document focuses on inter-domain SAV mechanisms that validate and filter packets without modifying data plane packets. This scope limitation is intentional, since allowing packet modification would introduce additional design, forwarding, interoperability, and deployment considerations beyond the problem space studied in this document. Therefore, SAV mechanisms based on data packet modification are outside the scope of this document.

# Terminology {#terminology}

{:vspace}
SAV table:
: The table of prefixes that indicates the validity of a specific source IP address or source IP prefix per interface. Sometimes the terms 'RPF (Reverse Path Forwarding) list' or 'SAV rules' are used interchangeably with 'SAV table'. 

Improper Block:
: The validation results in packets with legitimate source addresses being blocked improperly due to an inaccurate SAV table. (The terms 'improper block' and 'false positive' are used synonymously.)

Improper Permit: 
: The validation results in packets with spoofed source addresses being permitted improperly due to an inaccurate SAV table. (The terms 'improper permit' and 'false negative' are used synonymously.)

Customer Cone:
: The Customer Cone (CC) of a given AS, denoted as AS-A, includes: (1) AS-A itself, (2) AS-A's direct customers (ASes), (3) The customers of AS-A's direct customers (indirect customers), (4) And so on, recursively, following all chains of provider-to-customer (P2C) links down the hierarchy.

Prefixes in the CC:
: IP prefixes permitted by their owners to be originated by, or used as source addresses for data traffic originated from, one or more ASes within the CC.  

SAV-related Information:
: Routing information (e.g., RIBs and FIBs populated by routing protocols or by the local configuration information -- described below -- provided by the AS operator) and objects published in the Resource Public Key Infrastructure (RPKI) that were originally proposed for non-SAV purposes but may also be used for SAV. The RPKI objects include existing RPKI object types (e.g., ROAs and ASPAs) as well as any new types that may be proposed.

SAV-specific Information:
: Information dedicated to SAV, which may be defined and exchanged between ASes using potentially new inter-AS communication protocol or an extension of an existing protocol. The information may also take the form of new RPKI object type(s). It may also come from the local configuration information provided by the AS operator.

Configuration Information: 
: This information is configured locally by the AS operator. For example, an AS provisions (suballocates) prefixes p1 and p2 for a non-BGP customer network, which also owns an RIR-allocated prefix p3. The customer instructs the AS to advertise p1 via eBGP on the public Internet, restrict p2 strictly to internal use (in the customer network), and refrain from advertising p3 while still allowing it to source outbound traffic. The AS locally configures these prefixes accordingly. This configuration information is valuable for both intra-domain SAV to permit expected prefixes and inter-domain SAV at other interfaces to block unexpected prefixes. 
Configuration that populates the RIB or FIB (e.g., static routes) is SAV-related information; configuration made for SAV (e.g., p3 above) is SAV-specific information.
      
<!-- The AS uses this configuration information locally for route origination and SAV filtering purposes. The configuration information can be viewed partly as SAV-related information (e.g., prefixes p1, p2) and partly as SAV-specific information (e.g., prefix p3). -->

Direct Server Return (DSR): 
: A traffic delivery model commonly used by Content Delivery Networks (CDNs) that use anycast service addresses while delivering data from edge locations that do not announce those addresses. In such deployments, a request is received by the anycast server, but the response is sent directly by another server (i.e., the edge server) with the anycast service address as the source address, rather than the address used to reach the edge server. This can create a legitimate hidden-prefix scenario.

# Existing Inter-domain SAV Mechanisms {#SAV_methods}

Inter-domain SAV is typically performed at the AS level (on a per neighbor-AS-interface basis) and can be deployed at AS border routers (ASBRs) to prevent source address spoofing. There are various mechanisms available to implement inter-domain SAV for anti-spoofing ingress filtering {{nist}} {{manrs}} {{isoc}}, which are reviewed in this section.

* ACL-based ingress filtering {{RFC3704}}: ACL-based ingress SAV filtering is a technique that relies on ACL rules to filter packets based on their source addresses. The ACL rules may be generated based on local configuration information ({{terminology}}), possibly combined with other sources. However, ACL-based ingress SAV filtering, when not automated, introduces significant operational overhead, as ACL rules need to be updated in a timely manner to reflect prefix or routing changes in the inter-domain routing system. One may think of using ACL (perhaps erroneously) as a denylist on a provider interface to block source prefixes that are clearly invalid in the inter-domain routing context, such as internal-use-only prefixes of the SAV-performing AS, IANA special purpose prefixes, and unallocated IPv4/IPv6 prefixes. But it is impractical to store and maintain a very large and dynamically varying set of unallocated IPv6 prefixes. Instead, it may be more practical, for example, to compute an ACL denylist containing the internal-use-only prefixes and prefixes originated exclusively by the SAV-performing AS and subtract the denylist from a SAV table computed by a uRPF method. Also, for the interfaces with a customer AS, the ACL-only method is impractical while other techniques (using uRPF as described below) are more effective. ACL-based ingress SAV filtering (ACL allowlist) has applicability in scenarios such as (1) directly connected subnets with hosts, or (2) broadband cable, fiber-optic cable, or digital subscriber access loop (DSL) access networks. In these cases, where the service provider should have a clear knowledge of IP address prefixes provisioned (and configured) to manage those services, the ACL-only method in an allowlist form is applicable.

* uRPF-based mechanisms: A class of SAV mechanisms are based on Unicast Reverse Path Forwarding (uRPF) {{RFC3704}} {{RFC8704}}. The core idea of uRPF for SAV is to exploit the symmetry of inter-domain routing: in many cases, the best next hop for a destination is also the best previous hop for the source. In other words, if a packet arrives from a certain interface, the source address of that packet should be reachable via the same interface, according to the FIB. However, symmetry in routing does not always hold in practice, and to address cases where it does not hold, many enhancements and modes of uRPF have evolved. Different modes of uRPF have different levels of strictness and flexibility, and network operators can choose from them to suit particular network scenarios. These modes are briefly described as follows:

  * Strict uRPF {{RFC3704}}: Strict uRPF is the most stringent mode. It permits a packet only if it has a source address that is covered by a prefix in the FIB, and the next hop for that prefix is the same interface that the packet arrived on. This mode can be deployed at customer interfaces in some scenarios, e.g., a directly connected single-homed stub customer AS {{nist}}.
  
  * Loose uRPF {{RFC3704}}: Loose uRPF verifies that the source address of a packet is routable on the Internet by matching it with one or more prefixes in the FIB, regardless of the interface on which the packet arrives. If the source address is not routable, Loose uRPF discards the packet. Loose uRPF is typically deployed at the provider interfaces of an AS to block packets with source addresses from prefixes that are not routed on the global Internet (e.g., IANA-allocated private-use addresses, unallocated IPv6 addresses, multicast addresses, etc.). If the FIB contains a default route, Loose uRPF permits packets with any source address, unless the implementation excludes the default route from the check or applies additional interface-based checks ({{RFC3704}}, Sections <xref target="RFC3704" section="2.4" sectionFormat="bare"/> and <xref target="RFC3704" section="2.5" sectionFormat="bare"/>).

  * Feasible Path uRPF (FP-uRPF) {{RFC3704}}: Unlike Strict uRPF, which requires the packet to arrive on the exact best return path, FP-uRPF allows a packet to pass as long as the router could reach that source address through the interface it arrived on (based on the feasible routes in the Adj-RIBs-In {{RFC4271}}), even if the route is not the primary route (per best path selection). This makes it more effective in multi-homed environments where asymmetric routing is common, as it prevents legitimate traffic from being dropped simply because it did not take the "best" path back to the sender.
  
  * Enhanced Feasible Path uRPF with Algorithm A (EFP-uRPF Alg-A) {{RFC8704}}: EFP-uRPF Alg-A expands the list of valid source addresses for a specific interface by including all prefixes associated with any Origin AS that is reachable through that interface. Instead of only accepting prefixes directly advertised on a link, the router identifies all the origin ASes present in the BGP updates received on that interface and then permits any prefix from those same ASes that it sees elsewhere in its Adj-RIBs-In (associated with all neighbors &mdash; customers, providers, peers). This "Origin AS-based" approach provides significantly more flexibility than strict or FP-uRPF {{RFC3704}}, as it accounts for cases where an AS in the CC may send traffic for one of its prefixes over a link where it only advertised a different prefix (multi-homing and asymmetric routing scenarios).

  * Enhanced Feasible Path uRPF with Algorithm B (EFP-uRPF Alg-B) {{RFC8704}}: EFP-uRPF Alg-B provides even greater flexibility (compared to EFP-uRPF Alg-A) by aggregating all customer interfaces into a single "customer group" for validation purposes. The router first identifies all unique prefixes and origin ASes associated with all directly connected customer interfaces using only the Adj-RIBs-In associated with them. It then constructs a comprehensive RPF list (SAV table) that includes every prefix originated by those ASes, regardless of whether those prefixes were learned via customer, peer, or transit provider links. This list is applied uniformly across all customer-facing interfaces, attempting to ensure that legitimate traffic from a multihomed AS in the CC is never dropped, even if the traffic arrives on a different customer-facing port than the one where the specific prefix was advertised. In comparison to EFP-uRPF Alg-A, this method (Alg-B) reduces the possibility of improper block but at the expense of increased possibility of improper permit, i.e., reduced directionality.
  
  * Virtual Routing and Forwarding (VRF) uRPF {{RFC4364}} {{urpf}} {{manrs}}: VRF uRPF uses a separate VRF table for each external BGP peer and is only a way of implementation for a SAV table.

As described in <xref target="RFC8704" sectionFormat="comma" section="3.5"/>, the RPF lists constructed by EFP-uRPF Alg-A and Alg-B can also be augmented with ROA and reliable Internet Routing Registry (IRR) data. For Alg-A, prefixes obtained from these sources are added to a customer interface's RPF list only if at least one route with the corresponding Origin AS has been received on that interface. For Alg-B, such prefixes are added to the shared RPF list if the corresponding Origin AS has been observed in routes received on any customer interface. This augmentation can reduce improper blocking by including additional legitimate source prefixes. However, it still relies on BGP-derived Origin AS information to determine which customer interfaces can accept these prefixes.

# Gap Analysis {#gap}

The inadequacies of inter-domain SAV mechanisms can be characterized along three dimensions: improper block (false positives), improper permit (false negatives), and operational overhead. An ideal inter-domain SAV mechanism must block all spoofing traffic while permitting legitimate traffic in all scenarios of interest. However, in some cases, existing SAV mechanisms may unintentionally block legitimate traffic or permit spoofing traffic. This section aims to conduct a gap analysis of existing SAV mechanisms for different types of interfaces under various scenarios to identify their technical limitations.

## SAV at Customer Interfaces {#sav_at_cust}

To prevent source address spoofing on customer interfaces, operators can enable ACL-based ingress filtering, or uRPF-based mechanisms such as Strict uRPF, FP-uRPF, or EFP-uRPF. However, the ACL method typically has high operational overhead. The uRPF-based mechanisms may cause improper block in two inter-domain scenarios: Limited Propagation of a Prefix (LPP) and Hidden Prefix (HP). They may also cause improper permit in the scenarios of source address spoofing within a CC. One example of LPP scenarios is when an AS attaches NO_EXPORT {{RFC1997}} BGP Community to some prefixes (routes) forwarded to some upstream providers (in multi-homing scenarios) (see {{noexp}}). Sometimes this scenario occurs by selectively propagating different sets of prefixes to different upstream providers. The Hidden Prefix scenario is typically associated with the Direct Server Return (DSR) scenario; anycast prefix in a Content Delivery Network (CDN) application is not announced by the AS where the DSR (edge server) is located (see {{dsrp}}). Source address spoofing within a CC scenario arises when a prefix at one AS in the CC is spoofed from another AS in the same CC ({{spoofing_within_cc}}). It is recognized that unless there is full adoption of SAV in the CC of the interface in consideration, improper permit is not fully preventable in the case of source address spoofing within a CC.

{{customer_gap}} provides an overview of the gaps associated with the ACL method, Strict uRPF, FP-uRPF, and EFP-uRPF for SAV at customer interfaces in the Limited Propagation of a Prefix, Hidden Prefix, and source address spoofing within CC scenarios mentioned above. Illustrations and analyses of these gaps are provided in {{noexp}}, {{dsrp}}, and {{spoofing_within_cc}}, respectively.    

~~~~~~~~~~
+--------------------+------------+-----------+-------+--------+
|Traffic & Scenarios |     ACL    |Strict uRPF|FP-uRPF|EFP-uRPF|
+----------+---------+------------+-----------+-------+--------+
|Legitimate|   LPP   |            |                            |
|Traffic   +---------+            |       Improper Block       |
|          |   HP    |    High    |         possible           |
+----------+---------+Operational-+-------------------+--------+
|          |         |  Overhead  |                   |Improper|
|Spoofed   |  no SCC |            |                   |Permit  |
|Traffic   |         |            |   Functions as    |only for|
|          |         |            |      Expected     |EFP-uRPF|
|          |         |            |                   |Alg-B   |
+----------+---------+            +-------------------+--------+
|Spoofed   |   SCC   |            |                            |
|Traffic   |         |            |       Improper Permit      |
|          |         |            |    (in partial deployment) |
+----------+---------+------------+----------------------------+

LPP = Limited Propagation of a Prefix
HP = Hidden Prefix 
SCC = Spoofing within a CC
'Functions as Expected' connotes the absence of improper permit. 
It also connotes low operational overhead. 
~~~~~~~~~~
{: #customer_gap title="The gaps of ACL-based ingress filtering, Strict uRPF, FP-uRPF, and EFP-uRPF for customer interfaces for the scenarios of interest."}

### Limited Propagation of a Prefix Scenario {#noexp}

In inter-domain networks, some prefixes may not propagate from a customer to all its providers due to various factors, such as the use of NO_EXPORT or NO_ADVERTISE Communities {{RFC1997}}, or some other selective-export policies. In these cases, it is possible that a prefix (route) announcement in the CC associated with a customer interface has limited propagation in the CC and is not received on that interface. Then the prefix is invisible in BGP at that interface but the traffic with source address in that prefix may still be received on that interface. This can give rise to improper block when performing SAV with existing mechanisms. 
These mechanisms include Strict uRPF, FP-uRPF, and EFP-uRPF Alg-A; the following analysis uses EFP-uRPF Alg-A.

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
             \           |               \           \
     P1[AS 1] \          |                \           \
     NO_EXPORT \         |                 \           \
                \(C2P)   |(C2P)        (C2P)\      (C2P)\
              +----------------+          +----------------+
              |  AS 1(P1, P6)  |          |    AS 5(P5)    |
              +----------------+          +----------------+
~~~~~~~~~~
{: #no-export title="Limited propagation of a prefix caused by NO_EXPORT."} 

 In the scenario of {{no-export}}, AS 1 is a customer of AS 2; AS 1 and AS 2 are customers of AS 4; AS 4 is a customer of AS 3; and AS 5 is a customer of both AS 3 and AS 4. AS 1 advertises prefix P1 to AS 2 with the NO_EXPORT community attribute attached, preventing AS 2 from further propagating the route for prefix P1 to AS 4. Consequently, AS 4 only learns the route for prefix P1 from AS 1 in this scenario. Suppose AS 1 and AS 4 have deployed inter-domain SAV while other ASes have not, and AS 4 has deployed EFP-uRPF at its customer interfaces. 

 If AS 4 deploys EFP-uRPF Alg-A at customer interfaces, it will require packets with source addresses in P1 or P6 to only arrive on the interface with AS 1. When AS 1 sends legitimate packets with source addresses in P1 or P6 to AS 4 via AS 2, AS 4 improperly blocks these packets. The same improper block problem occurs with the use of Strict uRPF or FP-uRPF.

 This improper blocking by EFP-uRPF Alg-A persists even when its RPF lists are augmented with ROA or reliable IRR data as described in <xref target="RFC8704" section="3.5" sectionFormat="comma"/>. Although such data may associate P1 or P6 with AS 1, AS 4 does not receive any BGP route with Origin AS 1 on its customer interface facing AS 2. Therefore, the augmentation does not add these prefixes to the RPF list for that interface.

 EFP-uRPF Alg-B, which {{RFC8704}} recommends for customer interfaces, avoids the improper block in this scenario even without ROA/IRR augmentation because AS 1, the origin AS of those prefixes, is seen on another customer interface of AS 4. However, Alg-B may still cause improper blocking when the origin AS of the prefix is not seen on any customer interface of the validating AS, and its tolerance comes at the cost of directionality ({{spoofing_within_cc}}).
 Furthermore, in such cases, the ROA/IRR augmentation described in {{RFC8704}} cannot resolve the problem. 
 
 <!-- EFP-uRPF with Alg-B can avoid the improper block in this specific scenario, but even this SAV method would have the improper block if the Traffic Engineering (TE) at AS 1 is such that none of the customer interfaces at AS 4 receives a route for P1 (or P6). -->    

### Hidden Prefix Scenario {#dsrp}

CDNs use the concepts of anycast {{RFC4786}}{{RFC7094}} and DSR to improve the quality of service by placing edge servers with content closer to users. An anycast IP address is assigned to devices in different locations, and incoming requests are routed to the closest anycast server location. Usually, only locations with rich connectivity announce the anycast IP address through BGP. The CDN server receives requests from users and creates tunnels to the edge servers, from where content is sent directly to users. DSR requires edge servers to use the anycast IP address as the source address in response packets. However, the ASes serving the edge servers do not announce the anycast prefixes through BGP, so the anycast prefix is hidden (invisible in BGP) on the customer interface side at intermediate ASes which &mdash; with existing inter-domain SAV mechanisms &mdash; would improperly block the response packets.

{{dsr}} illustrates a DSR scenario where the anycast IP prefix P7 is advertised by AS 3 through BGP. In this example, AS 3 is the provider of AS 4 and AS 5; AS 4 is the provider of AS 1, AS 2, and AS 5; and AS 2 is the provider of AS 1. Suppose AS 1, AS 2, and AS 3 have deployed inter-domain SAV. When a user at AS 2 sends a request to the anycast destination IP, the forwarding path is AS 2->AS 4->AS 3. The anycast server in AS 3 receives the request and tunnels it to the edge servers in AS 1. Finally, the edge server sends the content packets to the user with source addresses in prefix P7. The forwarding path for the content packets is AS 1->AS 2. 
Since AS 2 learns the route for P7 from AS 4 rather than AS 1, Strict uRPF and FP-uRPF at the customer interface of AS 2 facing AS 1 will improperly block these legitimate response packets.

EFP-uRPF Alg-A and Alg-B also encounter improper blocking in this scenario, even when the ROA or IRR augmentation described in <xref target="RFC8704" sectionFormat="comma" section="3.5"/>, is applied. Specifically, P7 is originated by AS 3, while AS 2 does not receive any route with Origin AS 3 from its customer interfaces. Therefore, ROA or IRR data associating P7 with AS 3 would not cause P7 to be added to the RPF list for the customer interface facing AS 1.

In contrast, Loose uRPF at AS 2 would permit the response packets, since P7 is present in its FIB and Loose uRPF does not require the incoming interface to match the reverse path. However, this flexibility comes at the expense of directionality in SAV.

~~~~~~~~~~
                                +----------------+
                Anycast Server+-+  AS 3(P3, P7)  |
                                +-+/\----+/\+----+
                                   /       \
                       / P3[AS 3] /         \ P3[AS 3] \
                      / P7[AS 3] /           \ P7[AS 3] \
                     \/         / (C2P)       \         \/
                       +----------------+      \
                       |    AS 4(P4)    |       \
                       ++/\+--+/\+--+/\++        \
                         /     |      \           \
       / P3[AS 4, AS 3] /      |       \           \
      / P7[AS 4, AS 3] /       |        \           \
     \/               / (C2P)  |         \ P5[AS 5]  \ P5[AS 5]
      +----------------+       |          \           \    
User+-+    AS 2(P2)    |       | P1[AS 1]  \           \
      +----------+/\+--+       | P6[AS 1]   \           \
                   \           |             \           \
           P6[AS 1] \          |              \           \
            P1[AS 1] \         |               \           \
                      \(C2P)   |(C2P)      (C2P)\      (C2P)\
                    +---------------+         +----------------+
       Edge Server+-+  AS 1(P1, P6)  |        |    AS 5(P5)    |
                    +----------------+        +----------------+
P7 is the anycast prefix and is originated only by AS 3 via BGP.
Note that the prefix route propagations relevant to the DSR
scenario are depicted; not all prefix propagations are depicted.
~~~~~~~~~~
{: #dsr title="A Direct Server Return (DSR) scenario."}

Further, there are cases of specific prefixes that may be exclusively used as source addresses (legitimately) without being advertised via BGP by any AS. While different from DSR scenarios, these cases similarly result in existing inter-domain SAV mechanisms improperly blocking legitimate traffic originating from such prefixes.

### Source Address Spoofing within a Customer Cone Scenario {#spoofing_within_cc}

In general, improper permit of spoofed packets in source address spoofing within a CC scenarios is unavoidable for various uRPF-based methods in partial deployment. For example, consider a topology in which AS 1 and AS 2 are customers of AS 3; and AS 3 is a customer of AS 4. AS 1 and AS 2 originate prefixes P1 and P2, respectively. AS 4 performs SAV on its customer interface with AS 3. P1 and P2 are announced from AS 3 to AS 4 and they would be included in the SAV table (allowlist) of AS 4 with any SAV mechanism. Assume AS 3 does not enforce SAV. Now as an example of source address spoofing within a CC, if AS 2 spoofs AS 1's prefix P1 and sends the spoofed packets to AS 4 (via AS 3), there is no way for AS 4 to detect the spoofed traffic. AS 4's SAV cannot differentiate between the spoofed and the legitimate packets that have source address in P1. In a source address spoofing within a CC scenario of this nature, the only recourse for blocking the spoofed traffic is for AS 3 also to be upgraded to do SAV, i.e., deployment of SAV closer to the source of spoofing.           

Another scenario is highlighted in {{customer-spoofing}} while using EFP-uRPF Alg-B method on customer interfaces. This scenario is not source address spoofing within a CC from the perspective of an individual customer interface of AS 4, but it is source address spoofing within a CC from the perspective of AS 4 looking across all its customer interfaces. EFP-uRPF Alg-B relaxes directionality to reduce (or eliminate) false positives and that makes it more susceptible to source address spoofing within a CC (per the latter perspective). This is expected because EFP-uRPF Alg-B somewhat conservatively applies the same relaxed SAV table across all customer interfaces.

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
                 P6[AS 2, AS 1] /     |      \           \
                P1[AS 2, AS 1] /      |       \           \
                     P2[AS 2] /       |        \           \
                             / (C2P)  |         \ P5[AS 5]  \ P5[AS 5]
             +----------------+       |          \           \    
Spoofer(P5')-+    AS 2(P2)    |       | P1[AS 1]  \           \
             +----------+/\+--+       | P6[AS 1]   \           \
                          \           |             \           \
                  P6[AS 1] \          |              \           \
                   P1[AS 1] \         |               \           \
                             \(C2P)   |(C2P)      (C2P)\      (C2P)\
                           +----------------+        +----------------+
                           |  AS 1(P1, P6)  |        |    AS 5(P5)    |
                           +----------------+        +----------------+
P5' is the spoofed source prefix P5 by the spoofer which is inside of 
AS 2 or connected to AS 2 through other ASes.
~~~~~~~~~~
{: #customer-spoofing title="A scenario of source address spoofing within a customer cone."}

In {{customer-spoofing}}, the source address spoofing takes place within AS 4's CC, where the spoofer, which is inside of AS 2 or connected to AS 2 through other ASes, sends spoofing traffic with spoofed source addresses in P5 to AS 3 along the path AS 2 -> AS 4 -> AS 3. The arrows in {{customer-spoofing}} illustrate the commercial relationships between ASes. AS 3 serves as the provider for AS 4 and AS 5, while AS 4 acts as the provider for AS 1, AS 2, and AS 5. Additionally, AS 2 is the provider for AS 1. Suppose AS 4 and AS 5 have deployed inter-domain SAV, while the other ASes have not.

If AS 4 deploys EFP-uRPF Alg-B at its customer interfaces, it will allow packets with source addresses in P5 to originate from AS 1, AS 2, and AS 5. Consequently, AS 4 will improperly permit the spoofed packets from AS 2, enabling them to propagate further.

In the scenario of {{customer-spoofing}}, Strict uRPF, FP-uRPF, and EFP-uRPF Alg-A &mdash; applied on the customer interfaces &mdash; work effectively to block the spoofed packets from AS 2. This is because these mechanisms have a stronger directionality property than EFP-uRPF Alg-B.


## SAV at Peer Interfaces {#sav_at_peer}

SAV is used at peer interfaces for validating the traffic entering the validating AS and destined for the AS's customer cone.
The data packets received from a customer or lateral peer AS must have source addresses belonging only to the prefixes in the CC of that AS. 
In both cases, the focus is on discovering all prefixes in the CC of the neighbor AS.
So, in principle, the SAV techniques suitable on customer interfaces may also be used on peer interfaces, especially EFP-uRPF Alg-A or Alg-B, which are more accommodative of asymmetric routing.
Indeed, asymmetric routing is thought to be prevalent for peer interfaces.
If SAV techniques suitable for customer interfaces are considered for peer interfaces, then the gap analysis of {{sav_at_cust}} would also be applicable to the SAV for the peer interfaces.
However, due to increased concern about asymmetric routing, network operators may conservatively use the same relaxed SAV techniques for peer interfaces as those for provider interfaces, e.g., Loose uRPF ({{sav_at_prov}}).
In that case, the gap analysis of {{sav_at_prov}} would also be applicable to the SAV for peer interfaces.         

## SAV at Provider Interfaces {#sav_at_prov} 

SAV is used at provider interfaces for validating the traffic entering the AS and destined for the AS's customer cone. {{provider_peer_gap}} summarizes the gaps of ACL-based ingress filtering and Loose uRPF for SAV at provider interfaces in the scenarios of interest. ACL-based ingress filtering may effectively block spoofing traffic from a provider AS, while appropriately allowing legitimate traffic, but it has high operational overhead. On the other hand, Loose uRPF correctly permits legitimate traffic, but it can also mistakenly allow spoofing traffic to pass through. 

In {{provider_peer_gap}}, spoofing from providers refers to a scenario in which spoofed traffic comes from provider ASes, either because they originated it or because they forwarded the spoofed traffic that propagated from their neighbor ASes. The spoofed prefix may belong to (originated by) any AS in the Internet other than the spoofing AS; it may even belong to an AS in the customer cone of the validating AS (example below).

~~~~~~~~~~
+------------------------+------------+---------------+
|   Traffic & Scenarios  |     ACL    |   Loose uRPF  |
+----------+-------------+------------+---------------+
|Legitimate|             |            |  Functions    |
|Traffic   |     --      |    High    |  as Expected  |
+----------+-------------+Operational +---------------+
|Spoofed   |   Spoofing  |  Overhead  |               |
|Traffic   |     from    |   (HOO)    |Improper Permit|
|          |   Providers |            |               |
+----------+-------------+------------+---------------+

'Functions as Expected' connotes the absence of improper block.
It also connotes low operational overhead.
~~~~~~~~~~
{: #provider_peer_gap title="The gaps of ACL-based ingress filtering and Loose uRPF at provider interfaces in the scenarios of interest."}

{{provider-spoofing}} illustrates a scenario of spoofing from providers and is used to analyze the gaps of ACL-based ingress filtering and Loose uRPF.

~~~~~~~~~~
                          +----------------+
            Spoofer(P1')+-+    AS 3(P3)    |
                          +-+/\----+/\+----+
                             /       \
                            /         \ 
                           /           \
                          / (C2P)       \
                 +----------------+      \
                 |    AS 4(P4)    |       \
                 ++/\+--+/\+--+/\++        \
    P6[AS 2, AS 1] /     |      \           \
   P1[AS 2, AS 1] /      |       \           \
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
{: #provider-spoofing title="A scenario of source address spoofing from provider AS."}

In {{provider-spoofing}}, the spoofer which is inside of AS 3 or connected to AS 3 through other ASes forges the source addresses in P1 and sends the spoofing traffic to the destination addresses in P2 at AS 2. AS 1 is a customer of AS 2; AS 1 and AS 2 are customers of AS 4; AS 4 is a customer of AS 3; and AS 5 is a customer of both AS 3 and AS 4. Suppose AS 1 and AS 4 have deployed inter-domain SAV, while the other ASes have not.

Using an ACL-only method in the form of a denylist at the provider interface of AS 4 (facing AS 3) is impractical (incurs a very high operational overhead) as mentioned in {{SAV_methods}}.

Applying Loose uRPF at the provider interface of AS 4 (facing AS 3) can greatly reduce the operational overhead because it uses the FIB as the information source for allowed prefixes, and can adapt to changes in the network to prevent false positives (improper blocking). 
However, using Loose uRPF at AS 4 will naturally permit packets with source addresses in P1 (since P1 is present in the FIB) and hence will not prevent the improper permit of the spoofed packets from AS 3 ({{provider-spoofing}}).
This is an expected limitation of Loose uRPF.

## Gap Analysis Summary {#problem}

{{problem_sum}} provides a comprehensive summary of the gap analyses presented above. It highlights the scenarios where existing inter-domain SAV mechanisms may encounter issues, including instances of improper blocking of legitimate traffic, improper permitting of spoofing traffic, or high operational overhead. The various entries in the table in {{problem_sum}} can be traced back to the terminology and analyses presented in {{gap}}.   

~~~~~~~~~~
+--------+----------+-----------+----------+----------+-----------+
|Problems|    ACL   |   Strict  |  Loose   |  FP-uRPF |  EFP-uRPF |
|        |          |   uRPF    |  uRPF    |          |           |
|        |(CI or PI)|   (CI)    |  (PI)    |   (CI)   |    (CI)   |
+--------+----------+-----------+----------+----------+-----------+
|Improper|  YES/NO  |    YES    |   NO**   |    YES   |    YES*  |
|Block   |(manual   | (LPP, HP) |          | (LPP, HP)| (LPP, HP) |
|        |operator  |           |          |          |           |
|        |diligence)|           |          |          |           |
+--------+----------+-----------+----------+----------+-----------+
|Improper|  YES/NO  |NO (no SCC)|   YES    |NO(no SCC)|NO (Alg-A, |
|Permit  |(manual   |YES (SCC)  |(Spoofing |YES (SCC) |no SCC)    |
|        |operator  |           |  from    |          |YES (Alg-B,|
|        |diligence)|           |Providers)|          |no SCC)    |
|        |          |           |          |          |YES (SCC)  |
+--------+----------+-----------+----------+----------+-----------+
|        |   YES    |                                             |
|  HOO   |  (Any    |                     NO                      |
|        |Scenarios)|                                             |
+--------+----------+---------------------------------------------+
CI = Customer Interface
PI = Provider Interface
HOO = High Operational Overhead
LPP = Limited Propagation of a Prefix
HP = Hidden Prefix  
SCC = Spoofing within a CC  
Alg-A = EFP-uRPF Algorithm A  
Alg-B = EFP-uRPF Algorithm B  
** Typically, an HP (like DSR prefixes) is hidden on the CIs
   but received on a provider or peer interface; 
   hence included in the FIB and that helps avoid
   improper block for Loose uRPF.   
* In the LPP scenario of Figure 2, EFP-uRPF Alg-A causes
  improper blocking even with ROA/IRR augmentation, while
  Alg-B avoids it even without augmentation. Alg-B may
  still cause improper blocking in other LPP scenarios.
  In the HP scenario of Figure 3, both algorithms may
  cause improper blocking even with ROA/IRR augmentation.  
~~~~~~~~~~
{: #problem_sum title="Summary of the gap analyses of existing inter-domain SAV mechanisms."}

New proposals for SAV should aim to fill in the following problem areas (gaps) found in the currently standardized SAV methods (found in IETF RFCs): 

* Improper block: Strict uRPF, FP-uRPF, and EFP-uRPF (EFP-uRPF Alg-B less so) suffer from improper block (false positives) in two inter-domain scenarios: Limited Propagation of a Prefix (e.g., NO_EXPORT and some other selective-export scenarios) and Hidden Prefix (e.g., CDN/DSR scenario).

* Improper permit: With some existing uRPF-based SAV mechanisms, improper permit (false negatives) can happen on any type of interface (customer, lateral peer, or provider). Specifically, if the method relaxes the directionality constraint {{RFC3704}} {{RFC8704}} to try to achieve zero improper blocking, the possibility of improper permit increases. (Note: It is recognized that unless there is full adoption of SAV in the CC of the interface in consideration, improper permit is not fully preventable in scenarios where source address spoofing occurs from within the CC, i.e., a prefix at one AS in the CC is spoofed from another AS in the same CC.)

* High operational overhead: ACL-based ingress SAV filtering, when not automated, introduces significant operational overhead, as it needs to update ACL rules manually to adapt to prefix or routing changes in a timely manner. The high operational overhead issue does not pertain to existing uRPF-based mechanisms.  

The limitations of existing uRPF-based mechanisms arise from their reliance on BGP data. Although {{RFC8704}} (<xref target="RFC8704" sectionFormat="comma" section="3.5"/>) augments EFP-uRPF with ROA and reliable IRR data, this augmentation still requires the corresponding origin AS to be observed in BGP routes received on the relevant customer interface (Alg-A) or any customer interface (Alg-B). Consequently, improper blocking may persist in certain LPP and HP scenarios.
With the availability of authoritative SAV-related information, plus the potential for SAV-specific information ({{terminology}}), it would be possible to develop comprehensive new SAV algorithms or mechanisms to overcome the existing gaps.

# Requirements for New Inter-domain SAV Mechanisms {#req}

This section outlines the technical and operational requirements for new inter-domain SAV mechanisms, including considerations for their deployment and operation.

## Accurate Validation

Any new inter-domain SAV mechanism must provide improved SAV accuracy in terms of improper block and improper permit over existing mechanisms. It must achieve zero improper blocking (i.e., avoid false positives) in the Limited Propagation of a Prefix and Hidden Prefix scenarios ({{sav_at_cust}}), after the SAV table has converged, provided that the information it relies on is available.
Further, it must improve the directionality of filtering (i.e., achieve greater rejection of spoofed traffic) over existing mechanisms.
The requirement applies for all directions of AS peering (customer, provider, and peer).

## Reducing Operational Overhead

Any new inter-domain SAV mechanism should be able to automatically detect changes in the SAV-related information ({{terminology}}) and/or SAV-specific information ({{terminology}}) required for generating the SAV table, obtain the updated information, and use the updated information to generate the SAV table.

## Early Adopters Benefit in Incremental/Partial Deployment

Any new inter-domain SAV mechanism must not assume pervasive adoption of the SAV method, the SAV-related information, or the SAV-specific information. It should benefit early adopters by providing effective protection from spoofing of source addresses even in partial deployment.
Where the SAV-related or SAV-specific information a new mechanism relies on is absent for a prefix or an AS, the mechanism should not improperly block more traffic than the existing mechanism it replaces (e.g., EFP-uRPF Alg-B {{RFC8704}} on customer interfaces).

## Providing Necessary Security Guarantee

SAV-related information, e.g., routing information and the existing RPKI signed objects, may be used to design more accurate SAV mechanisms. Such information must be protected during both its creation and dissemination (the BGP security community is already diligent about this). If any new inter-domain SAV mechanism introduces or uses SAV-specific information, security mechanisms must exist to prevent malicious injection or alteration of the SAV-specific information.
Such mechanisms should also bound the freshness of SAV-specific information and allow its distribution to be limited to the ASes that need it.

## Efficient Convergence

Any new inter-domain SAV mechanism should achieve efficient convergence of the SAV table after any relevant changes occur in the SAV-related information or SAV-specific information used by the mechanism.
In this context, convergence refers to the stabilization of the SAV tables on the AS-to-AS interfaces performing SAV.
It is essential that any new SAV mechanism converges to the correct updated SAV table in a proper manner, minimizing both improper block and improper permit during the process.

* Additional considerations: Any new SAV proposal should keep the following guidelines in consideration. The initial SAV table computation (prior to SAV enforcement installation) must be performed only when the data used in the computation (e.g., routing tables, RPKI data) are in a stable (i.e., non-transient) state from the local AS's perspective. For instance, if an ASBR in the SAV performing AS is newly deployed or restarted, then sufficient time must be allowed for routing state convergence to complete before the initial SAV table computation is performed. Similar statement applies for the ASBR with regard to RPKI data convergence. After SAV enforcement installation, the SAV table should be dynamically and quickly updated when new prefixes are discovered (e.g., from BGP Updates or RPKI data updates) for inclusion in the table. However, for removing a prefix from the SAV table (e.g., due to route withdrawal or RPKI changes), applying hysteresis (<xref target="RFC8704" sectionFormat="comma" section="3.6.2"/>) should be considered in the SAV design.

## Troubleshooting Guidance

Any new inter-domain SAV solution document should incorporate troubleshooting guidelines within its operational considerations section, following the guidance in {{I-D.ietf-opsawg-rfc5706bis}}. 
Because an ASBR enforces SAV based strictly on a statically or dynamically computed SAV table, it cannot inherently detect its own validation errors, such as false positives (improper blocks) or false negatives (improper permits). 
Consequently, a new mechanism should provide counters of packets dropped by SAV (per interface and, where feasible, per prefix), a means to export samples of dropped packets, a monitoring-only mode that logs without dropping, and a way to inspect the computed SAV table, including where each entry came from (e.g., BGP, RPKI, local configuration, and SAV-specific information), so that operators can detect improper blocks before, and in addition to, complaints from affected parties.

## Deployment Considerations for Private ASes

Private ASes were mentioned in {{intro}}. A public AS may serve as a transit gateway for a routing zone utilizing private ASes. These private AS numbers are not visible in external eBGP advertisements because the transit public AS strips them from the AS_PATH using standard vendor features, such as remove-private-as {{Cisco}} or remove-private {{Juniper}}.   

A routing zone or network utilizing only private ASes can still adopt any new inter-domain SAV solutions developed for the public Internet. Implementing these solutions in such environments requires suitable operational modifications, such as employing SLURM (Simplified Local Internet Number Resource Management with the RPKI) {{RFC8416}} to add local ROA prefix assertions for private ASes. Any new inter-domain SAV solution document should incorporate recommendations for suitable operational modifications for this scenario, as necessary.

# Security Considerations {#Security}

The SAV table will be generated based on SAV-related information and/or SAV-specific information. If such information is poisoned by attackers, or if stale or replayed SAV-specific information is used, the resulting SAV table will be inaccurate. Consequently, legitimate traffic may be dropped improperly, or spoofing traffic may be permitted improperly. 
In particular, an attacker able to influence the information used by another AS for SAV table generation may cause improper blocking of legitimate traffic, resulting in denial of service.
SAV-specific information may disclose prefixes, routing policy, or business relationships that an AS deliberately keeps out of BGP.
For SAV mechanisms that use BGP data as input for generating SAV tables, the use of applicable BGP routing security methods is important.
Relevant BGP security methods include route origin validation {{RFC6811}}, BGPsec {{RFC8205}}, and route leak prevention {{RFC9234}}.

# IANA Considerations {#IANA}

This document does not request any IANA allocations.

# Contributors

Nan Geng  
  Huawei  
  Beijing,
  China   
  Email: gengnan@huawei.com

--- back

# Acknowledgements {#Acknowledgements}
{: numbered="false"}

Many thanks to Jared Mauch, Barry Greene, Fang Gao, Anthony Somerset, Yuanyuan Zhang, Igor Lubashev, Alvaro Retana, Joel Halpern, Ron Bonica, Aijun Wang, Michael Richardson, Li Chen, Gert Doering, Mingxing Liu, John O'Brien, Roland Dobbins, Paul Vixie, Amir Herzberg, Jeffrey Haas, Xueyan Song, and Jianping Wu for their reviews, comments, and suggestions.
The authors also thank the IESG for their reviews and comments, which helped improve the clarity of this document.
Apologies to any others whose names the authors may have inadvertently missed mentioning. 
