###############################################################################
# OpenVAS Vulnerability Test
# $Id: xampp_multiple_vuln_jun_09.nasl 8187 2017-12-20 07:30:09Z teissa $
#
# XAMPP Multiple Vulnerabilities June 2009
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

tag_summary = "XAMPP is prone to multiple vulnerabilities.

1. showcode.php Local File Include Vulnerability

An attacker can exploit this vulnerability to view files and execute
local scripts in the context of the webserver process. This may aid
in further attacks.

2. Multiple Cross Site Scripting Vulnerabilities

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

3. Multiple SQL Injection Vulnerabilities

Exploiting these issues could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

These issues affect XAMPP 1.6.8 and prior; other versions may be
affected as well.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100483");
 script_version("$Revision: 8187 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-02-02 21:07:02 +0100 (Tue, 02 Feb 2010)");
 script_bugtraq_id(37997,37998,37999);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("XAMPP Multiple Vulnerabilities June 2009");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37997");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37998");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37999");
 script_xref(name : "URL" , value : "http://websecurity.com.ua/3230/");
 script_xref(name : "URL" , value : "http://websecurity.com.ua/3220/");
 script_xref(name : "URL" , value : "http://websecurity.com.ua/3257/");
 script_xref(name : "URL" , value : "http://www.apachefriends.org/en/xampp.html");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_xampp_detect.nasl");
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

if(!version = get_kb_item(string("www/", port, "/XAMPP")))exit(0);

if(!isnull(version)) {

  if(version_is_less_equal(version: version, test_version: "1.6.8")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
