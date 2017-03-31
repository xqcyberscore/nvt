###############################################################################
# OpenVAS Vulnerability Test
# $Id: AproxEngine_37515.nasl 5245 2017-02-09 08:57:08Z teissa $
#
# AproxEngine Multiple Remote Input Validation Vulnerabilities
#
# Authors:
# Michael Meyer
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

tag_summary = "AproxEngine is prone to multiple input-validation vulnerabilities,
including SQL-injection, HTML-injection, directory-traversal, and email-
spoofing issues.

Attackers can exploit these issues to execute arbitrary script code in
the context of the webserver, compromise the application, obtain
sensitive information, steal cookie-based authentication credentials
from legitimate users of the site, modify the way the site is
rendered, perform certain unauthorized actions in the context of a
user, access or modify data, or exploit latent vulnerabilities in the
underlying database.

Attackers may require administrative privileges to exploit some of
these issues.

AproxEngine 5.3.04 and 6.0 are vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(100426);
 script_version("$Revision: 5245 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-09 09:57:08 +0100 (Thu, 09 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-01-05 18:50:28 +0100 (Tue, 05 Jan 2010)");
 script_bugtraq_id(37515);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("AproxEngine Multiple Remote Input Validation Vulnerabilities");


 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("AproxEngine_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37515");
 script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2009-2/");
 script_xref(name : "URL" , value : "http://www.aprox.de/index.php?id=1");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/508641");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(!version = get_kb_item(string("www/", port, "/AproxEngine")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "5.3.04")) {
      security_message(port:port);
      exit(0);
  } 
  
  else if(version_is_equal(version: vers, test_version: "6")) {

    dir = matches[2];

    url = string(dir, "/engine/inc/sql_login.inc");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if( buf == NULL )exit(0);

    if(egrep(pattern: "AproxEngine Version V6 build 03.12.2009", string: buf)) { #  build 03.12.2009 is vulnerable. builds after 03.12.2009 are patched.
      security_message(port:port);
      exit(0);
    }  
  }  
}

exit(0);
