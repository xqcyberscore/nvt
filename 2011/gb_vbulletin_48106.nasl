###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vbulletin_48106.nasl 3911 2016-08-30 13:08:37Z mime $
#
# vBulletin vBExperience 'sortorder' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "vBulletin vBExperience is prone to a cross-site scripting
vulnerability because it fails to sufficiently sanitize user-
supplied data.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

vBulletin vBExperience 3.0 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(103171);
 script_version("$Revision: 3911 $");
 script_tag(name:"last_modification", value:"$Date: 2016-08-30 15:08:37 +0200 (Tue, 30 Aug 2016) $");
 script_tag(name:"creation_date", value:"2011-06-06 13:42:32 +0200 (Mon, 06 Jun 2011)");
 script_bugtraq_id(48106);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("vBulletin vBExperience 'sortorder' Parameter Cross Site Scripting Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/48106");
 script_xref(name : "URL" , value : "http://www.vbulletin.org/forum/showthread.php?t=171014");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if vBulletin vBExperience is prone to a cross-site scripting vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("vbulletin_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_mandatory_keys("vBulletin/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if( ! dir = get_dir_from_kb(port:port, app:"vBulletin"))exit(0);

url = string(dir,'/xperience.php?sortfield=xr&sortorder="><script>alert(/openvas-xss-test/);</script>'); 

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\);</script>",check_header:TRUE)) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
