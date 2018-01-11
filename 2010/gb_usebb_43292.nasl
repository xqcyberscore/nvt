###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_usebb_43292.nasl 8356 2018-01-10 08:00:39Z teissa $
#
# UseBB Forum and Topic Feed Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

tag_summary = "UseBB is prone to a security-bypass vulnerability.

Remote attackers can exploit this issue to gain access to restricted
forum and feed content.

Versions prior to UseBB 1.0.11 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100812");
 script_version("$Revision: 8356 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-09-20 15:31:27 +0200 (Mon, 20 Sep 2010)");
 script_bugtraq_id(43292);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

 script_name("UseBB Forum and Topic Feed Security Bypass Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43292");
 script_xref(name : "URL" , value : "http://www.usebb.net/community/topic.php?id=2501");
 script_xref(name : "URL" , value : "http://www.usebb.net/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_usebb_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"UseBB")) {

  if(version_is_less_equal(version: vers, test_version: "1.0.11")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
