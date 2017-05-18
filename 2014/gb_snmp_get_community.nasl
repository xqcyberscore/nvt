###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_snmp_get_community.nasl 5740 2017-03-28 03:23:03Z ckuerste $
#
# Report default community names of the SNMP Agent
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10264");
 script_cve_id("CVE-1999-0516");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 5740 $");
 script_name("Report default community names of the SNMP Agent");

 script_tag(name:"last_modification", value:"$Date: 2017-03-28 05:23:03 +0200 (Tue, 28 Mar 2017) $");
 script_tag(name:"creation_date", value:"2014-03-12 10:10:24 +0100 (Wed, 12 Mar 2014)");
 script_category(ACT_GATHER_INFO);
 script_family("SNMP");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("snmp_default_communities.nasl");
 script_require_udp_ports("Services/udp/snmp", 161);
 script_mandatory_keys("SNMP/detected_community","SNMP/port");

 script_tag(name : "impact" , value : "If an attacker is able to guess a PUBLIC community string,
 they would be able to read SNMP data (depending on which MIBs are installed) from the remote
 device. This information might include system time, IP addresses, interfaces, processes
 running, etc.

 If an attacker is able to guess a PRIVATE community string (WRITE or 'writeall'
 access), they will have the ability to change information on the remote machine.
 This could be a huge security hole, enabling remote attackers to wreak complete
 havoc such as routing network traffic, initiating processes, etc.  In essence,
 'writeall' access will give the remote attacker full administrative rights over
 the remote machine.

 Note that this test only gathers information and does not attempt to write to
 the remote device.  Thus it is not possible to determine automatically whether
 the reported community is public or private.

 Also note that information made available through a guessable community string
 might or might not contain sensitive data.  Please review the information
 available through the reported community string to determine the impact of this
 disclosure.");
 script_tag(name : "solution" , value : "Determine if the detected community string is a private
 community string. Determine whether a public community string exposes sensitive information.
 Disable the SNMP service if you don't use it or change the default community string.");
 script_tag(name : "summary" , value : "Simple Network Management Protocol (SNMP) is a protocol
 which can be used by administrators to remotely manage a computer or network
 device.  There are typically 2 modes of remote SNMP monitoring. These modes
 are roughly 'READ' and 'WRITE' (or PUBLIC and PRIVATE).");

 script_tag(name:"qod_type", value:"remote_vul");

 exit(0);
}

port = get_kb_item("SNMP/port");
if( ! port ) exit( 0 );

cos = make_list( get_kb_list("SNMP/detected_community") );
if( ! cos ) exit( 99 );

report = 'SNMP Agent responded as expected when using the following community name:\n\n';

foreach co ( cos )
{
  report += co + '\n';
  a++;
}

if( a > 0 )
{
  security_message( port:port, data:report, proto:'udp' );
  exit( 0 );
}

exit( 99 );
