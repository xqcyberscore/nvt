###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cscart_sql_injection_vuln.nasl 4561 2016-11-18 06:13:39Z ckuerste $
#
# CS-Cart 'product_id' Parameter SQL Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:cs-cart:cs-cart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901123");
  script_version("$Revision: 4561 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-18 07:13:39 +0100 (Fri, 18 Nov 2016) $");
  script_tag(name:"creation_date", value:"2010-06-16 08:26:33 +0200 (Wed, 16 Jun 2010)");
  script_cve_id("CVE-2009-4891");
  script_bugtraq_id(34048);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CS-Cart 'product_id' Parameter SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49154");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8184");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_cscart_detect.nasl");
  script_mandatory_keys("cs_cart/installed");

  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to perform SQL Injection attack
  and gain sensitive information.

  Impact Level: Application");
  script_tag(name : "affected" , value : "CS-Cart version 2.0.0 Beta 3");
  script_tag(name : "insight" , value : "The flaw is caused by improper validation of user-supplied input via the
  'product_id' parameter to index.php that allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code.");
  script_tag(name : "solution" , value : "Upgrade to CS-Cart version 2.0.15 or later,
  For updates refer to http://www.cs-cart.com/");
  script_tag(name : "summary" , value : "The host is running CS-Cart and is prone to SQL injection
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!csVer = get_app_version(cpe: CPE, port: port))
  exit(0);

## Check for CS-Cart  version 2.0.0 Beta 3
if(version_is_equal(version:csVer, test_version:"2.0.0.beta3")) {
  report = report_fixed_ver(installed_version: csVer, fixed_version: "2.0.15");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
