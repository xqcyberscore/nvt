# OpenVAS Vulnerability Test
# $Id: weblogic_adm_servlet.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: WebLogic management servlet
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Thanks to Sullo who supplied a sample of WebLogic banners
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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

tag_summary = "The remote web server is WebLogic

An internal management servlet which does not properly
check user credential can be accessed from outside, allowing
a cracker to change user passwords, and even upload or download
any file on the remote server.

In addition to this, there is a flaw in WebLogic 7.0 which may 
allow users to delete empty subcontexts.

*** Note that OpenVAS only checked the version in the server banner
*** So this might be a false positive.


Solutions : 
- apply Service Pack 2 Rolling Patch 3 on WebLogic 6.0
- apply Service Pack 4 on WebLogic 6.1
- apply Service Pack 2 on WebLogic 7.0 or 7.0.0.1";

if(description)
{
 script_id(11486);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2003-1095");
 script_bugtraq_id(7122, 7124, 7130, 7131);
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 
 
 name = "WebLogic management servlet";
 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/weblogic");
 script_xref(name : "URL" , value : "http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA03-28.jsp");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);

if ("WebLogic " >!< banner) exit(0);	 # Not WebLogic

# All those tests below have NEVER been validated!
# Here are the banner we got:
# WebLogic 5.1.0 04/03/2000 17:13:23 #66825
# WebLogic 5.1.0 Service Pack 10 07/11/2001 21:04:48 #126882
# WebLogic 5.1.0 Service Pack 12 04/14/2002 22:57:48 #178459
# WebLogic 5.1.0 Service Pack 6 09/20/2000 21:03:19 #84511
# WebLogic 5.1.0 Service Pack 9 04/06/2001 12:48:33 #105983 - 128 bit domestic version
# WebLogic WebLogic Server 6.1 SP1  09/18/2001 14:28:44 #138716
# WebLogic WebLogic Server 6.1 SP3  06/19/2002 22:25:39 #190835
# WebLogic WebLogic Temporary Patch for CR067505 02/12/2002 17:10:21

# I suppose that this kind of thing might exist
if (" Temporary Patch for CR096950" >< banner) exit(0);

if (banner =~ "WebLogic .* 6\.1 ")
{
  if (" SP4 " >!< banner) security_message(port);
  exit(0);
}

if (banner =~ "WebLogic .* 6\.0 ")
{
  if (banner !~ " SP[3-9] " && " SP2 RP3 " >!< banner) security_message(port);
  exit(0);
}

if (banner =~ "WebLogic .* 7\.0(\.0\.1)? ")
{
  if (banner !~ " SP[2-9]") security_message(port);
  exit(0);
}

