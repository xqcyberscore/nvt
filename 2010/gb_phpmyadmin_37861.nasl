###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_37861.nasl 6705 2017-07-12 14:25:59Z cfischer $
#
# phpMyAdmin 'unserialize()' Remote Code Execution Vulnerability
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

tag_summary = "phpMyAdmin is prone to a vulnerability that lets attackers execute
arbitrary code in the context of the webserver process. This may
facilitate unauthorized access or privilege escalation; other attacks
are also possible.

Versions prior to phpMyAdmin 3.0.0 or 2.11.10 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100589";
CPE = "cpe:/a:phpmyadmin:phpmyadmin";


if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 6705 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 16:25:59 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2010-04-20 13:41:39 +0200 (Tue, 20 Apr 2010)");
 script_bugtraq_id(37861);
 script_cve_id("CVE-2009-4605");

 script_name("phpMyAdmin 'unserialize()' Remote Code Execution Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37861");
 script_xref(name : "URL" , value : "http://www.phpmyadmin.net/");
 script_xref(name : "URL" , value : "http://www.phpmyadmin.net/home_page/security/PMASA-2010-3.php");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("phpMyAdmin/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)) {

  if(version_is_less(version: vers, test_version: "2.11.10")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
