###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cobbler_53666.nasl 5999 2017-04-21 09:02:32Z teissa $
#
# Cobbler Remote Command Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "Cobbler is prone to a remote command-injection vulnerability.

Attackers can exploit this issue to execute arbitrary commands in the
context of the affected application.";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103515";
CPE = "cpe:/a:michael_dehaan:cobbler";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(53666);
 script_cve_id("CVE-2012-2395");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 5999 $");

 script_name("Cobbler Remote Command Injection Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53666");
 script_xref(name : "URL" , value : "http://freshmeat.net/projects/cobbler");
 script_xref(name : "URL" , value : "https://bugs.launchpad.net/ubuntu/+source/cobbler/+bug/978999");
 script_xref(name : "URL" , value : "https://github.com/cobbler/cobbler/issues/141");
 script_xref(name : "URL" , value : "https://github.com/cobbler/cobbler/commit/6d9167e5da44eca56bdf42b5776097a6779aaadf");

 script_tag(name:"last_modification", value:"$Date: 2017-04-21 11:02:32 +0200 (Fri, 21 Apr 2017) $");
 script_tag(name:"creation_date", value:"2012-07-12 16:50:33 +0200 (Thu, 12 Jul 2012)");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_cobbler_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("Cobbler/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!version = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(version_is_equal(version:version, test_version:"2.2.0")) {

  security_message(port:port);
  exit(0);

}  

exit(0);

