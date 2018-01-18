###############################################################################
# OpenVAS Vulnerability Test
# $Id: zope_37765.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# Zope 'standard_error_message' Cross-Site Scripting Vulnerability
#
# Authors:
# Michael Meyer
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-03-29
# Updated the CVE
#
#Copyright:
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

tag_summary = "Zope is prone to a cross-site scripting vulnerability because the
application fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may help the attacker steal cookie-based authentication
credentials and launch other attacks.

The issue affects versions prior to Zope 2.12.3, 2.11.6, 2.10.11,
2.9.12, and 2.8.12.";

tag_solution = "The vendor has released updates. Please see the references for
details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100455");
 script_version("$Revision: 8447 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-01-20 10:52:14 +0100 (Wed, 20 Jan 2010)");
 script_bugtraq_id(37765);
 script_cve_id("CVE-2010-1104");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Zope 'standard_error_message' Cross-Site Scripting Vulnerability");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37765");
 script_xref(name : "URL" , value : "https://mail.zope.org/pipermail/zope-announce/2010-January/002229.html");
 script_xref(name : "URL" , value : "http://www.zope.org");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("zope/banner");
 script_require_ports("Services/www", 8080);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
if("Server: Zope/" >!< banner)exit(0);

version = eregmatch(pattern: "Server: Zope/\(Zope ([0-9.]+)", string: banner);
if(isnull(version[1]))exit(0);

if(version_in_range(version: version[1], test_version: "2.12", test_version2: "2.12.3")  ||
   version_in_range(version: version[1], test_version: "2.11", test_version2: "2.11.5")  ||
   version_in_range(version: version[1], test_version: "2.10", test_version2: "2.10.10") ||
   version_in_range(version: version[1], test_version: "2.9", test_version2: "2.9.11")   ||
   version_in_range(version: version[1], test_version: "2.8", test_version2: "2.8.11"))  {

    security_message(port:port);
    exit(0);

}

exit(0);

