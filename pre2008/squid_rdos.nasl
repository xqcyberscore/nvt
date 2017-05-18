# OpenVAS Vulnerability Test
# $Id: squid_rdos.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: Squid remote denial of service
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Updated: 04/07/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote squid caching proxy, according to its version number, may be 
  vulnerable to a remote denial of service.
  This flaw is due to an input validation error in the SNMP module.
  An attacker can exploit this flaw to crash the server with a specially
  crafted UDP packet.";

tag_solution = "Upgrade to squid 2.5.STABLE7 or newer";

#  Ref: iDEFENSE 10.11.04

if(description)
{
  script_id(15463);
  script_version("$Revision: 6056 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(11385);
  script_cve_id("CVE-2004-0918");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Squid remote denial of service");

 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_dependencies("secpod_squid_detect.nasl");
  script_require_ports("Services/http_proxy",3128, 8080);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");

port = get_kb_item("Services/http_proxy");
if(!port){
  port = 3128;
}

if(!get_port_state(port)){
  port = 8080;
}

data =get_kb_item(string("www/", port, "/Squid"));
if(!data){
  exit(0);
}

if(egrep(pattern:"2\.([0-4]|5\.STABLE[0-6])", string:data))
{  security_message(port);
   exit(0);
}
