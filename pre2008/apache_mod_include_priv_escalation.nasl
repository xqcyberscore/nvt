# OpenVAS Vulnerability Test
# $Id: apache_mod_include_priv_escalation.nasl 5621 2017-03-20 13:56:15Z cfi $
# Description: Apache mod_include privilege escalation
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

tag_summary = "The remote web server appears to be running a version of Apache that is older
than version 1.3.33.

This version is vulnerable to a local buffer overflow in the get_tag()
function of the module 'mod_include' when a specially crafted document 
with malformed server-side includes is requested though an HTTP session.

Successful exploitation can lead to execution of arbitrary code with 
escalated privileges, but requires that server-side includes (SSI) is enabled.";

tag_solution = "Disable SSI or upgrade to a newer version when available.";

#  Ref: Crazy Einstein

if(description)
{
 script_id(15554);
 script_version("$Revision: 5621 $");
 script_tag(name:"last_modification", value:"$Date: 2017-03-20 14:56:15 +0100 (Mon, 20 Mar 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(11471);
 script_cve_id("CVE-2004-0940");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");

 name = "Apache mod_include privilege escalation";

 script_name(name);


 summary = "Checks for version of Apache";

 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 script_family("Web Servers");
 script_dependencies("http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(!port)exit(0);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.|3\.([0-9][^0-9]|[0-2][0-9]|3[0-2])))", string:serv))
 {
   security_message(port);
   exit(0);
 }
