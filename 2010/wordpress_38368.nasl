###############################################################################
# OpenVAS Vulnerability Test
# $Id: wordpress_38368.nasl 6705 2017-07-12 14:25:59Z cfischer $
#
# WordPress Trashed Posts Information Disclosure Vulnerability
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

tag_summary = "WordPress is prone to an information-disclosure vulnerability because
it fails to properly restrict access to trashed posts.

An attacker can exploit this vulnerability to view other authors'
trashed posts, which may aid in further attacks.

Versions prior to WordPress 2.9.2 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100505";
CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 6705 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 16:25:59 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2010-02-24 18:35:31 +0100 (Wed, 24 Feb 2010)");
 script_bugtraq_id(38368);
 script_cve_id("CVE-2010-0682");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

 script_name("WordPress Trashed Posts Information Disclosure Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38368");
 script_xref(name : "URL" , value : "http://tmacuk.co.uk/?p=180");
 script_xref(name : "URL" , value : "http://wordpress.org/development/2010/02/wordpress-2-9-2/");
 script_xref(name : "URL" , value : "http://wordpress.org/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_wordpress_detect_900182.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("wordpress/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "2.9.2")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
