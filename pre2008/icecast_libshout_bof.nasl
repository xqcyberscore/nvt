# OpenVAS Vulnerability Test
# $Id: icecast_libshout_bof.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: ICECast libshout remote buffer overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
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

tag_summary = "The remote server runs a version of ICECast, an open source 
streaming audio server, which is older than version 1.3.9.

Icecast and the libshout library are affected by a remote buffer overflow because they do
not properly check bounds of data send from clients. 

As a result of this vulnerability, it is possible for a remote attacker to
cause a stack overflow and then execute arbitrary code with the privilege of the server.

*** OpenVAS reports this vulnerability using only
*** information that was gathered.";

tag_solution = "Upgrade to a newer version.";

#  Ref: Matt Messier <mmessier@prilnari.com> and John Viega <viega@list.org>

if(description)
{
 script_id(15398);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4735);
 script_cve_id("CVE-2001-1229");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 
 name = "ICECast libshout remote buffer overflow";
 script_name(name);
 



 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
		
 family = "Buffer overflow";
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("icecast/banner");
 script_require_ports("Services/www", 8000);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:8000);
if(!port) exit(0);

banner = tolower(get_http_banner(port:port));
if ( ! banner ) exit(0);
if("icecast/" >< banner &&
   egrep(pattern:"icecast/1\.(0\.[0-4][^0-9]|1\.|3\.[0-8][^0-9])", string:banner))
      security_message(port);
