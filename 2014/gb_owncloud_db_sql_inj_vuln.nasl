###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_db_sql_inj_vuln.nasl 3554 2016-06-20 07:41:15Z benallard $
#
# ownCloud 'lib/db.php' SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:owncloud:owncloud";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804411";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3554 $");
  script_cve_id("CVE-2013-2045");
  script_bugtraq_id(59961);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-20 09:41:15 +0200 (Mon, 20 Jun 2016) $");
  script_tag(name:"creation_date", value:"2014-03-14 13:35:19 +0530 (Fri, 14 Mar 2014)");
  script_name("ownCloud 'lib/db.php' SQL Injection Vulnerability");

  tag_summary =
"This host is installed with ownCloud and is prone to SQL injection
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to the 'lib/db.php' script not properly sanitizing user
supplied input before using it in SQL queries.";

  tag_impact =
"Successful exploitation will allow remote attacker to inject or manipulate
SQL queries in the back-end database, allowing for the manipulation or
disclosure of arbitrary data.

Impact Level: Application";

  tag_affected =
"ownCloud Server 5.0.x before 5.0.6";

  tag_solution =
"Upgrade to ownCloud 5.0.6 or later,
For updates refer to http://owncloud.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2013/q2/324");
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/oC-SA-2013-019");
  script_summary("Check the version ownCloud vulnerable or not");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_mandatory_keys("owncloud/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ownPort = "";
ownVer = "";

## get the port
if(!ownPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check the port status
if(!get_port_state(ownPort)){
  exit(0);
}

## Get the location
if(!ownVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:ownPort)){
  exit(0);
}

if(version_in_range(version:ownVer, test_version:"5.0", test_version2:"5.0.5"))
{
  security_message(port:ownPort);
  exit(0);
}
