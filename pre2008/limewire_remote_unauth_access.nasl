# OpenVAS Vulnerability Test
# $Id: limewire_remote_unauth_access.nasl 5390 2017-02-21 18:39:27Z mime $
# Description: Lime Wire Multiple Remote Unauthorized Access
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

tag_summary = "The remote host seems to be running Lime Wire, a P2P file sharing program.

This version is vulnerable to remote unauthorized access flaws.
An attacker can access to potentially sensitive files on the 
remote vulnerable host.";

tag_solution = "Upgrade at least to version 4.8";

#  Ref: Kevin Walsh <kwalsh at cs.cornell.edu>

if(description)
{
 script_id(17973);
 script_version("$Revision: 5390 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(12802);
 script_cve_id("CVE-2005-0788", "CVE-2005-0789");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 name = "Lime Wire Multiple Remote Unauthorized Access";

 script_name(name);


 summary = "Checks for remote unauthorized access flaw in Lime Wire";

 script_summary(summary);

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");

 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 family = "Peer-To-Peer File Sharing";
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
 script_mandatory_keys("limewire/banner");
 script_require_ports(6346);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

if(!port)port = 6346;
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

serv = strstr(banner, "Server");
if(egrep(pattern:"limewire", string:serv, icase:TRUE))
{
  req = http_get(item:"/gnutella/res/C:\Windows\win.ini", port:port);
  soc = http_open_socket(port);
  if(soc)
  {
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);
   if("[windows]" >< r)
   {
    security_message(port);
    exit(0);
   }
  }
}
