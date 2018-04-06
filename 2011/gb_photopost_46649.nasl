###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_photopost_46649.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# PhotoPost PHP 'showgallery.php' Multiple Cross Site Scripting Vulnerabilities
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

tag_summary = "PhotoPost PHP is prone to multiple cross-site scripting
vulnerabilities because it fails to properly sanitize user-
supplied input.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may let the attacker steal cookie-based authentication
credentials and launch other attacks.

PhotoPost PHP 4.8c is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103104");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-03 13:33:12 +0100 (Thu, 03 Mar 2011)");
 script_bugtraq_id(46649);
 script_cve_id("CVE-2005-0274");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("PhotoPost PHP 'showgallery.php' Multiple Cross Site Scripting Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46649");
 script_xref(name : "URL" , value : "http://www.photopost.com");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/516793");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("photopost_detect.nasl");
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

if(!dir = get_dir_from_kb(port:port,app:"photopost"))exit(0);

url = string(dir, '/showgallery.php?si="<script>alert(/openvas-xss-test/)</script>"'); 

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>",check_header:TRUE)) {
   
  security_message(port:port);
  exit(0);

}

exit(0);
