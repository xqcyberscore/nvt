###############################################################################
# OpenVAS Vulnerability Test
# $Id: mt_37638.nasl 6705 2017-07-12 14:25:59Z cfischer $
#
# Movable Type Unspecified Security Bypass Vulnerability
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

tag_summary = "Movable Type is prone to an unspecified security-bypass vulnerability.

Very little is known about this issue at this time (06.01.2010). We will update
this BID as more information emerges.

This issue affects versions prior to 4.27 and 5.01.";

tag_solution = "The vendor has released fixes. Please see the references for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100430";
CPE = "cpe:/a:sixapart:movable_type";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 6705 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 16:25:59 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2010-01-06 18:07:55 +0100 (Wed, 06 Jan 2010)");
 script_bugtraq_id(37638);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

 script_name("Movable Type Unspecified Security Bypass Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37638");
 script_xref(name : "URL" , value : "http://www.movabletype.jp/blog/movable_type_501.html");
 script_xref(name : "URL" , value : "http://www.movabletype.org/");
 script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN09872874/index.html");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("mt_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("movabletype/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(vers =~ "^5\.") {
    if(version_is_less(version: vers, test_version: "5.01")) {
        security_message(port:port);
        exit(0);
    }
  } 
  else if(version_is_less(version: vers, test_version: "4.27")) {
    security_message(port:port);
    exit(0);
  }  
}

exit(0);
