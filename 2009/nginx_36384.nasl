###############################################################################
# OpenVAS Vulnerability Test
# $Id: nginx_36384.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# nginx HTTP Request Remote Buffer Overflow Vulnerability
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

tag_summary = "The 'nginx' program is prone to a buffer-overflow vulnerability
because the application fails to perform adequate boundary checks on
user-supplied data.

Attackers can exploit this issue to execute arbitrary code within the
context of the affected application. Failed exploit attempts will
result in a denial-of-service condition.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100276");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
 script_bugtraq_id(36384);
 script_cve_id("CVE-2009-2629");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("nginx HTTP Request Remote Buffer Overflow Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36384");
 script_xref(name : "URL" , value : "http://nginx.net/CHANGES-0.5");
 script_xref(name : "URL" , value : "http://nginx.net/CHANGES-0.6");
 script_xref(name : "URL" , value : "http://nginx.net/CHANGES-0.7");
 script_xref(name : "URL" , value : "http://nginx.net/CHANGES");
 script_xref(name : "URL" , value : "http://nginx.net/");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/180065");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("nginx_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("nginx/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!vers = get_kb_item(string("nginx/", port, "/version")))exit(0);
if(!isnull(vers) && vers >!< "unknown") {

  if(
     version_is_less(version: vers, test_version:"0.5.38")                      ||
     version_in_range(version:vers, test_version:"0.6", test_version2:"0.6.38") ||
     version_in_range(version:vers, test_version:"0.7", test_version2:"0.7.61") ||
     version_in_range(version:vers, test_version:"0.8", test_version2:"0.8.14")
    ) {

      security_message(port:port);
      exit(0);
  }

}

exit(0);     
