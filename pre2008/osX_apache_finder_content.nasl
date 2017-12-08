# OpenVAS Vulnerability Test
# $Id: osX_apache_finder_content.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: MacOS X Finder reveals contents of Apache Web files
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
# Modified by Noam Rathaus <noamr@securiteam.com>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2001 Matt Moore, Modified by Noam Rathaus
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

tag_summary = "MacOS X creates a hidden file, '.FBCIndex' in each directory that has been 
viewed with the Finder. This file contains the content of the files present 
in the directory, giving an attacker information on the HTML tags, JavaScript, 
passwords, or any other sensitive word used inside those files.";

tag_solution = "Use a <FilesMatch> directive in httpd.conf to restrict access to
'hidden' files:

<FilesMatch '^\.'>
Order allow, deny
Deny from all
</FilesMatch>

And restart Apache.";


if(description)
{
 script_id(10773); 
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2001-1446");
 script_bugtraq_id(3325);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 name = "MacOS X Finder reveals contents of Apache Web files";
 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
 
 script_copyright("This script is Copyright (C) 2001 Matt Moore, Modified by Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# Check for .FBCIndex in the root of the web site 
# Could be improved to use the output of webmirror.nasl to create a list of folders to try... 
# This is very important since most ROOT directories do not contain it! TODO

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 req = http_get(item:"/.FBCIndex", port:port); # Check in web root
 r = http_keepalive_send_recv(port:port, data:req);
 if("Bud2" >< r) 
 	security_message(port);
}
