###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_54443.nasl 6720 2017-07-13 14:25:27Z cfischer $
#
# WordPress Paid Memberships Pro Plugin 'memberslist-csv.php' Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "The Paid Memberships Pro plugin for WordPress is prone to an information-
disclosure vulnerability because it fails to sufficiently validate user-
supplied data.

An attacker can exploit this issue to obtain sensitive information
that may aid in further attacks.

Paid Memberships Pro 1.4.7 is vulnerable; other versions may also
be affected.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103520";
CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54443);
 script_version ("$Revision: 6720 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("WordPress Paid Memberships Pro Plugin 'memberslist-csv.php' Information Disclosure Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54443");
 script_xref(name : "URL" , value : "http://www.paidmembershipspro.com/2012/07/important-security-update-1-5/");

 script_tag(name:"last_modification", value:"$Date: 2017-07-13 16:25:27 +0200 (Thu, 13 Jul 2017) $");
 script_tag(name:"creation_date", value:"2012-07-16 12:51:36 +0200 (Mon, 16 Jul 2012)");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("secpod_wordpress_detect_900182.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("wordpress/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);
   
url = dir + '/wp-content/plugins/paid-memberships-pro/adminpages/memberslist-csv.php'; 

if(http_vuln_check(port:port, url:url,pattern:"username",extra_check:make_list("zipcode","address1","firstname"))) {
     
  security_message(port:port);
  exit(0);

}

exit(0);

