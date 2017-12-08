# OpenVAS Vulnerability Test
# $Id: snapstream_dir_trav.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Snapstream PVS web directory traversal
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CVE
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

tag_summary = "It is possible to read arbitrary files on the remote 
Snapstream PVS server by prepending ../../ in front on the 
file name.
It may also be possible to read ../ssd.ini which contains
many informations on the system (base directory, usernames &
passwords).";

tag_solution = "Upgrade your software or change it!";

# I wonder if this script should not be merged with web_traversal.nasl
# References:
# From: john@interrorem.com
# Subject: Snapstream PVS vulnerability
# To: bugtraq@securityfocus.com
# Date: Thu, 26 Jul 2001 08:23:51 +0100 (BST)

if(description)
{
 script_id(11079);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3100);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_cve_id("CVE-2001-1108");
 
 name = "Snapstream PVS web directory traversal";
 script_name(name);
 

 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");

 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8129);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# FP + other Directory Traversal scripts do the same thing
exit (0);

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:8129);
if(!port) exit(0);

if(!get_port_state(port)) exit(0);

fil[0] = "/../ssd.ini";
fil[1] = "/../../../../autoexec.bat";
fil[2] = "/../../../winnt/repair/sam";

for (i=0; i<3; i=i+1) {
  ok = is_cgi_installed_ka(port:port, item:fil[i]);
  if (ok) { security_message(port); exit(0); }
}


