###############################################################################
# OpenVAS Vulnerability Test
# $Id: dokeos_34928.nasl 4655 2016-12-01 15:18:13Z teissa $
#
# Dokeos Multiple Remote Input Validation Vulnerabilities
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "Dokeos is prone to multiple input-validation vulnerabilities, including
  SQL-injection, HTML-injection, cross-site scripting, and cross-site
  request-forgery issues.

  Attackers can exploit these issues to execute arbitrary script code
  in the context of the webserver, compromise the application, obtain
  sensitive information, steal cookie-based authentication credentials
  from legitimate users of the site, modify the way the site is
  rendered, perform certain unauthorized actions in the context of a
  user, access or modify data, or exploit latent vulnerabilities in
  the underlying database.

  Dokeos 1.8.5 is affected; prior versions may also be affected.";


if (description)
{
 script_id(100200);
 script_version("$Revision: 4655 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-01 16:18:13 +0100 (Thu, 01 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-05-14 12:53:07 +0200 (Thu, 14 May 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-2004");
 script_bugtraq_id(34928 );

 script_name("Dokeos Multiple Remote Input Validation Vulnerabilities");


 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("dokeos_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34928");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/dokeos")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "1.8.5")) {
    
      security_message(port:port);
      exit(0);

 }  

}  

exit(0);
