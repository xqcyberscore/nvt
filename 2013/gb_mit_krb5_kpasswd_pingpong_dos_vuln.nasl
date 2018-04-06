###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mit_krb5_kpasswd_pingpong_dos_vuln.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# MIT Kerberos 5 kpasswd UDP Packet Denial Of Service Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will allow attacker to cause a denial of service via
  a forged packet that triggers a communication loop.
  Impact Level: Application";

tag_affected = "MIT Kerberos 5 before 1.11.3";
tag_insight = "The flaw is caused due to the kpasswd application does not properly validate
  UDP packets before sending responses and can be exploited to exhaust CPU and
  network resources via the UDP 'ping-pong' attack.";
tag_solution = "Upgrade to MIT Kerberos 5 version 1.11.3 or later,
  For updates refer to http://web.mit.edu/kerberos";
tag_summary = "This host is running MIT Kerberos and is prone to denial of
  service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802056");
  script_version("$Revision: 9353 $");
  script_bugtraq_id(60008);
  script_cve_id("CVE-2002-2443");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-06-20 10:48:39 +0530 (Thu, 20 Jun 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("MIT Kerberos 5 kpasswd UDP Packet Denial Of Service Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53375");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2013/q2/316");
  script_xref(name : "URL" , value : "http://krbdev.mit.edu/rt/Ticket/Display.html?id=7637");
  script_xref(name : "URL" , value : "https://github.com/krb5/krb5/commit/cf1a0c411b2668c57c41e9c4efd15ba17b6b322c");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_require_udp_ports(464);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("network_func.inc");

## Variable Initialization
res = "";
sock = "";
crap_data = "";

## kpasswd UDP port
kpasswd_port = 464;

## Check UDP port status as get_udp_port_state() not working properly
if(!check_udp_port_status(dport:kpasswd_port)){
  exit(0);
}

## Check port status
sock = open_sock_udp(kpasswd_port);
if(!sock){
  exit(0);
}

## Some crap data
crap_data = crap(25);

send(socket:sock, data:crap_data);
res = recv(socket:sock, length:512);

## If kpasswd responds means it's vulnerable to ping-pong attack
if("kadmin" >< res && "changepw" >< res)
{
  security_message(port:kpasswd_port, protocol:"udp");
  exit(0);
}
