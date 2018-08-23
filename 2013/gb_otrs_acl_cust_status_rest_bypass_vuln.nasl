###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_acl_cust_status_rest_bypass_vuln.nasl 11082 2018-08-22 15:05:47Z mmartin $
#
# OTRS ACL-customer-status Ticket Restriction Bypass Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803927");
  script_version("$Revision: 11082 $");
  script_cve_id("CVE-2010-4763");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-08-22 17:05:47 +0200 (Wed, 22 Aug 2018) $");
  script_tag(name:"creation_date", value:"2013-09-22 10:18:31 +0530 (Sun, 22 Sep 2013)");
  script_name("OTRS ACL-customer-status Ticket Restriction Bypass Vulnerability");


  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to bypass
intended ACL restrictions on the (1) Status, (2) Service, and (3) Queue
via selections.

Impact Level: Application");
  script_tag(name:"vuldetect", value:"Get the installed version of OTRS with the help of detect NVT and check the
version is vulnerable or not.");
  script_tag(name:"insight", value:"An error exists in ACL-customer-status Ticket Type setting which fails to
restrict the ticket options after an AJAX reload");
  script_tag(name:"solution", value:"Upgrade to OTRS (Open Ticket Request System) version 3.0.0-beta1 or
later, For updates refer to http://www.otrs.com/en/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with OTRS (Open Ticket Request System) and is prone to
restriction bypass vulnerability.");
  script_tag(name:"affected", value:"OTRS (Open Ticket Request System) version before 3.0.0-beta1");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OTRS/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(vers = get_app_version(cpe:CPE, port:port))
{
  if(version_is_less(version: vers, test_version: "3.0.0.beta1"))
  {
      security_message(port:port);
      exit(0);
  }

}
