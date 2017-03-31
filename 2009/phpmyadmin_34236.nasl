###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpmyadmin_34236.nasl 5016 2017-01-17 09:06:21Z teissa $
#
# phpMyAdmin 'setup.php' PHP Code Injection Vulnerability
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

tag_summary = "phpMyAdmin is prone to a remote PHP code-injection vulnerability and
  to a cross-site scripting vulnerability.

  An attacker can exploit this issue to inject and execute arbitrary
  malicious PHP code in the context of the webserver process. This may
  facilitate a compromise of the application and the underlying
  system; other attacks are also possible.

  Versions prior to phpMyAdmin 2.11.9.5 and 3.1.3.1 are vulnerable.";

tag_solution = "Vendor updates are available. Please see http://www.phpmyadmin.net for more
  Information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100077";
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 5016 $");
 script_tag(name:"last_modification", value:"$Date: 2017-01-17 10:06:21 +0100 (Tue, 17 Jan 2017) $");
 script_tag(name:"creation_date", value:"2009-03-26 13:41:22 +0100 (Thu, 26 Mar 2009)");
 script_cve_id("CVE-2009-1151");
 script_bugtraq_id(34236,34251);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("phpMyAdmin Code Injection and XSS Vulnerability");


 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_mandatory_keys("phpMyAdmin/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34236");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34251");
 exit(0);
}


 include("http_func.inc");
 include("version_func.inc");
 include("host_details.inc");
  
 if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
 if(!get_port_state(port))exit(0);

 if(!version = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

   if (
       version_in_range(version:version, test_version:"2.11", test_version2:"2.11.9.4") ||
       version_in_range(version:version, test_version:"3.1", test_version2:"3.1.3.0")
      ) { 
        security_message(port:port);
	exit(0);
   }

exit(0);
