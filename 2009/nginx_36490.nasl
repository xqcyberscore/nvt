###############################################################################
# OpenVAS Vulnerability Test
# $Id: nginx_36490.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# nginx WebDAV Multiple Directory Traversal Vulnerabilities
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

tag_summary = "The 'nginx' program is prone to multiple directory-traversal
vulnerabilities because the software fails to sufficiently sanitize
user-supplied input.

An attacker can exploit these issues using directory-traversal strings
('../') to overwrite arbitrary files outside the root directory.

These issues affect nginx 0.7.61 and 0.7.62; other versions may also
be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100275");
 script_version("$Revision: 9350 $");
 script_cve_id("CVE-2009-3898");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
 script_bugtraq_id(36490);
 script_tag(name:"cvss_base", value:"4.9");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
 script_name("nginx WebDAV Multiple Directory Traversal Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36490");
 script_xref(name : "URL" , value : "http://nginx.net/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/506662");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("nginx_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("nginx/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

     
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!vers = get_kb_item(string("nginx/", port, "/version")))exit(0);
if(!isnull(vers) && vers >!< "unknown") {

  if(
     version_is_equal(version: vers, test_version: "0.7.61") ||
     version_is_equal(version: vers, test_version: "0.7.62")
    ) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
