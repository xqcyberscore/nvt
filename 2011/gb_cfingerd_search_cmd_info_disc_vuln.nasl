###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cfingerd_search_cmd_info_disc_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Cfingerd 'search' Command Information Disclosure Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application";
tag_affected = "Cfingerd version 1.2.2";
tag_insight = "The flaw exists due to an error in the finger service which allows to list
  all usernames on the host via 'search.**' command.";
tag_solution = "Upgrade to Cfingerd version 1.2.3 or later
  For updates refer to http://www.infodrom.org/projects/cfingerd/finger.php";
tag_summary = "This host is running Cfingerd service and is prone to information
  disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802323");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)");
  script_cve_id("CVE-1999-0259");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Cfingerd 'search' Command Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/1811");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/1997_2/0328.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Finger abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/finger", 79);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


## Get Finger Port
port = get_kb_item("Services/finger");
if(!port){
  port = 79;
}

## Check Port Status
if(! get_port_state(port)){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(port);
if(! soc){
  exit(0);
}

## Confirm Finger
banner = recv(socket:soc, length:2048, timeout:5);
if(banner) {
  exit(0);
}

## Send And Receive The Response
send(socket: soc, data: string("search.**\r\n"));
fingRes = recv(socket:soc, length:2048);
close(soc);

## Confirm Vulnerability
if("Finger" >< fingRes && "Username" >< fingRes && "root" >< fingRes){
  security_message(port);
}
