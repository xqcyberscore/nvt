###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_38707.nasl 5323 2017-02-17 08:49:23Z teissa $
#
# phpMyAdmin 'db_create.php' Cross Site Scripting Vulnerability
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

tag_summary = "phpMyAdmin is prone to a cross-site scripting vulnerability because it
fails to sufficiently sanitize user-supplied data.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

phpMyAdmin 3.3.0 is vulnerable; other versions may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100530";
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 5323 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-17 09:49:23 +0100 (Fri, 17 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-03-15 13:03:19 +0100 (Mon, 15 Mar 2010)");
 script_bugtraq_id(38707);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

 script_name("phpMyAdmin 'db_create.php' Cross Site Scripting Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38707");
 script_xref(name : "URL" , value : "http://www.phpmyadmin.net/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/510052");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_mandatory_keys("phpMyAdmin/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "3.3.0")) {
    security_message(port:port);
    exit(0);
  }   

}  
exit(0);
