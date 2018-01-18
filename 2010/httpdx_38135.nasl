###############################################################################
# OpenVAS Vulnerability Test
# $Id: httpdx_38135.nasl 8438 2018-01-16 17:38:23Z teissa $
#
# httpdx 'USER' Command Remote Format String Vulnerability
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

tag_summary = "The 'httpdx' program is prone to a remote format-string vulnerability.

An attacker may exploit this issue to execute arbitrary code within
the context of the affected application. Failed exploit attempts will
result in a denial-of-service condition.

The issue affects httpdx 1.5.2; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100491");
 script_version("$Revision: 8438 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-02-09 12:21:13 +0100 (Tue, 09 Feb 2010)");
 script_bugtraq_id(38135);
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

 script_name("httpdx 'USER' Command Remote Format String Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38135");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/httpdx/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_httpdx_server_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

     
include("http_func.inc");
include("version_func.inc");

httpdxPort = get_http_port(default:80);
if(!httpdxPort){
    exit(0);
}

httpdxVer = get_kb_item("httpdx/" + httpdxPort + "/Ver");
if(!isnull(httpdxVer))
{
    if(version_is_equal(version:httpdxVer, test_version:"1.5.2")){
      security_message(httpdxPort);
    }
}
