# OpenVAS Vulnerability Test
# $Id: apache_htpasswd_overflow.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Apache <= 1.3.33 htpasswd local overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Fixed by Tenable 26-May-2005:
#   - added BIDs 13777 and 13778
#   - extended banner check to cover 1.3.33 as well.
#   - edited description.
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

tag_summary = "The remote host appears to be running Apache 1.3.33 or older.

There is a local buffer overflow in the 'htpasswd' command in these
versions that may allow a local user to gain elevated privileges if
'htpasswd' is run setuid or a remote user to run arbitrary commands
remotely if the script is accessible through a CGI. 

*** Note that OpenVAS solely relied on the version number
*** of the remote server to issue this warning. This might
*** be a false positive";

tag_solution = "Make sure htpasswd does not run setuid and is not accessible
           through any CGI scripts.";

if(description)
{
 script_id(14771);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_bugtraq_id(13777, 13778);
 name = "Apache <= 1.3.33 htpasswd local overflow";

 script_name(name);
 
 
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 
 family = "Privilege escalation";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2004-10/0345.html");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include('global_settings.inc');

port = get_http_port(default:80);

if(get_port_state(port))
{
banner = get_http_banner(port: port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server:");
if(!serv)exit(0);

if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-1][0-9]|2[0-9]|3[0-3])))", string:serv))
 {
   security_message(port);
 } 
}
