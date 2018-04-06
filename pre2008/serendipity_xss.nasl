# OpenVAS Vulnerability Test
# $Id: serendipity_xss.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Serendipity XSS Flaw
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

tag_summary = "The remote version of Serendipity is vulnerable to cross-site scripting
attacks due to a lack of sanity checks on the 'searchTerm' parameter in
the 'compat.php' script.  With a specially crafted URL, an attacker can
cause arbitrary code execution in a user's browser resulting in a loss
of integrity.";

tag_solution = "Upgrade to Serendipity 0.7.1 or newer.";

#  Ref: Stefan Esser

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.15914";
CPE = "cpe:/a:s9y:serendipity";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.15914");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2004-2525");
 script_bugtraq_id(11790);
 script_xref(name:"OSVDB", value:"12177");
 script_name("Serendipity XSS Flaw");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 script_family("Web application abuses");
 script_dependencies("serendipity_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Serendipity/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://sourceforge.net/tracker/index.php?func=detail&aid=1076762&group_id=75065&atid=542822");
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# Test an install.
if(!loc = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

 req = http_get(item:string(loc, "/index.php?serendipity%5Baction%5D=search&serendipity%5BsearchTerm%5D=%3Cscript%3Efoo%3C%2Fscript%3E"), port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if (r =~ "HTTP/1\.. 200" && egrep(pattern:"<script>foo</script>", string:r))
 {
 	security_message(port);
 }

