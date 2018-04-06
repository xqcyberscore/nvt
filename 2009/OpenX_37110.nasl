###############################################################################
# OpenVAS Vulnerability Test
# $Id: OpenX_37110.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# OpenX Arbitrary File Upload Vulnerability
#
# Authors:
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

tag_summary = "OpenX is prone to a vulnerability that lets attackers upload arbitrary
files because the application fails to adequately validate user-
supplied input.

An attacker can exploit this vulnerability to upload arbitrary code
and execute it in the context of the webserver process. This may
facilitate unauthorized access or privilege escalation; other attacks
are also possible.

The issue affects OpenX 2.8.1 and prior.";

tag_solution = "Reportedly, the vendor fixed this issue in OpenX 2.8.2. Symantec has
not confirmed this information. Please contact the vendor for details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100364");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-11-25 11:49:08 +0100 (Wed, 25 Nov 2009)");
 script_tag(name:"cvss_base", value:"6.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
 script_cve_id("CVE-2009-4098");
 script_bugtraq_id(37110);

 script_name("OpenX Arbitrary File Upload Vulnerability");


 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("OpenX_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37110");
 script_xref(name : "URL" , value : "http://www.openx.org/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/508050");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(!version = get_kb_item(string("www/", port, "/openx")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "2.8.2")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
