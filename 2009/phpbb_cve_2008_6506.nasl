###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpbb_cve_2008_6506.nasl 5016 2017-01-17 09:06:21Z teissa $
#
# phpBB Account Re-Activation Authentication Bypass Vulnerability
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

tag_summary = "According to its version number, the remote version of phpbb
  is prone to an authentication-bypass vulnerability because it fails
  to properly enforce privilege requirements on some operations.

  Attackers can exploit this vulnerability to gain unauthorized access
  to the affected application, which may aid in further attacks.

  Versions prior to phpBB 3.0.4 are vulnerable.";

tag_solution = "Updates are available; please see http://www.phpbb.com/.";


if (description)
{
 script_id(100086);
 script_version("$Revision: 5016 $");
 script_tag(name:"last_modification", value:"$Date: 2017-01-17 10:06:21 +0100 (Tue, 17 Jan 2017) $");
 script_tag(name:"creation_date", value:"2009-03-29 17:14:47 +0200 (Sun, 29 Mar 2009)");
 script_bugtraq_id(32842);
 script_cve_id("CVE-2008-6506");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

 script_name("phpBB Account Re-Activation Authentication Bypass Vulnerability");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("phpbb_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/32842");
 script_xref(name : "URL" , value : "http://www.phpbb.com/");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
	version = matches[1];
        if (version_is_less(version:version, test_version:"3.0.4") ) {
	   security_message(port);
	   exit(0);
	}
}
