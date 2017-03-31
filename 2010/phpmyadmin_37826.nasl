###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpmyadmin_37826.nasl 5394 2017-02-22 09:22:42Z teissa $
#
# phpMyAdmin Insecure Temporary File and Directory Creation Vulnerabilities
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

tag_summary = "phpMyAdmin creates temporary directories and files in an insecure way.

An attacker with local access could potentially exploit this issue to
perform symbolic-link attacks, overwriting arbitrary files in the
context of the affected application.

Successful attacks may corrupt data or cause denial-of-service
conditions. Other unspecified attacks are also possible.

This issue affects phpMyAdmin 2.11.x (prior to 2.11.10.)";

tag_solution = "Updates are available. Please see the references for details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100450";
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 5394 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-22 10:22:42 +0100 (Wed, 22 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-01-18 11:34:48 +0100 (Mon, 18 Jan 2010)");
 script_bugtraq_id(37826);
 script_cve_id("CVE-2008-7251","CVE-2008-7252");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("phpMyAdmin Insecure Temporary File and Directory Creation Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37826");
 script_xref(name : "URL" , value : "http://www.phpmyadmin.net/home_page/index.php");
 script_xref(name : "URL" , value : "http://www.phpmyadmin.net/home_page/security/PMASA-2010-1.php");
 script_xref(name : "URL" , value : "http://www.phpmyadmin.net/home_page/security/PMASA-2010-2.php");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_mandatory_keys("phpMyAdmin/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "2.11.10")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
