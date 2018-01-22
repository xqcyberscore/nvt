###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sahana_38863.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# Sahana 'stream.php' Authentication Bypass Vulnerability
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

tag_summary = "Sahana is prone to an authentication-bypass vulnerability.

An attacker can exploit this issue to bypass authentication.
Successful exploits may lead to other attacks.

This issue affects Sahana 0.6.2.2; other versions may be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100544");
 script_version("$Revision: 8457 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-03-22 19:12:13 +0100 (Mon, 22 Mar 2010)");
 script_bugtraq_id(38863);
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2010-1191");

 script_name("Sahana 'stream.php' Authentication Bypass Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38863");
 script_xref(name : "URL" , value : "http://www.sahana.lk/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("sahana_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"sahana")) {

  if(version_is_equal(version: vers, test_version: "0.6.2.2")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
