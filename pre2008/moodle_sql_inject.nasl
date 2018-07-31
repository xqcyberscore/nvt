# OpenVAS Vulnerability Test
# $Id: moodle_sql_inject.nasl 10674 2018-07-30 08:24:18Z asteins $
# Description: Moodle SQL injection flaws
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

#  Ref: Moodle Team

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.15639");
 script_version("$Revision: 10674 $");
 script_tag(name:"last_modification", value:"$Date: 2018-07-30 10:24:18 +0200 (Mon, 30 Jul 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1424", "CVE-2004-1425", "CVE-2004-2232");
 script_bugtraq_id(11608, 11691, 12120);
 script_xref(name:"OSVDB", value:"11427");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Moodle SQL injection flaws");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 script_dependencies("gb_moodle_cms_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Moodle/Version");
 script_tag(name:"solution", value:"Upgrade to Moodle 1.4.3 or later.");
 script_tag(name:"summary", value:"The remote host is running a version of the Moodle suite, an open-source
course management system written in PHP, which is older than version 1.4.3.

The remote version of this software is vulnerable to SQL injection issue
in 'glossary' module due to a lack of user input sanitization.");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^(0\..*|1\.([0-4][^0-9]?|[0-4]\.[012][^0-9]?))$")
  {
	security_message(port);
	exit(0);
  }
}
