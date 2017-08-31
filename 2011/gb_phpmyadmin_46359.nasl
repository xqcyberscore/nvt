###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_46359.nasl 6945 2017-08-16 14:22:22Z cfischer $
#
# phpMyAdmin Bookmark Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "phpMyAdmin is prone to a security-bypass vulnerability that affects
bookmarks.

Successfully exploiting this issue allows a remote attacker to bypass
certain security restrictions and perform unauthorized actions.

Versions prior to phpMyAdmin 3.3.9.2 and 2.11.11.3 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103076";
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 6945 $");
 script_tag(name:"last_modification", value:"$Date: 2017-08-16 16:22:22 +0200 (Wed, 16 Aug 2017) $");
 script_tag(name:"creation_date", value:"2011-02-15 13:44:44 +0100 (Tue, 15 Feb 2011)");
 script_bugtraq_id(46359);
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2011-0986", "CVE-2011-0987");

 script_name("phpMyAdmin Bookmark Security Bypass Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46359");
 script_xref(name : "URL" , value : "http://www.phpmyadmin.net/");
 script_xref(name : "URL" , value : "http://www.phpmyadmin.net/home_page/security/PMASA-2011-2.php");

 script_tag(name:"qod_type", value:"remote_banner");
 script_summary("Determine if installed phpMyAdmin version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
 script_require_ports("Services/www", 80);
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
if(vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)) {

  if(vers =~ "^3\.") {
    if(version_is_less(version: vers, test_version: "3.3.9.2")) {
        security_message(port:port);
        exit(0);
    }
  } 
  
  else if(vers =~ "^2\.") {
    if(version_is_less(version: vers, test_version: "2.11.11.3")) {
      security_message(port:port);
      exit(0);
    }  
  }  

}

exit(0);
