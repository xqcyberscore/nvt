###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_database_listener_sec_bypass_vuln.nasl 6079 2017-05-08 09:03:33Z teissa $
#
# Oracle Database Server listener Security Bypass Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803960";
CPE = 'cpe:/a:oracle:database_server';

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6079 $");
  script_cve_id("CVE-2000-0818");
  script_bugtraq_id(1853);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2017-05-08 11:03:33 +0200 (Mon, 08 May 2017) $");
  script_tag(name:"creation_date", value:"2013-11-06 19:08:11 +0530 (Wed, 06 Nov 2013)");
  script_name("Oracle Database Server listener Security Bypass Vulnerability");

  tag_summary =
"This host is installed with Oracle Database Server and is prone to security
bypass vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of tnslsnr service and check it is
vulnerable or not.";

  tag_insight =
"A flaw exist in Oracle listener program, which allows attacker to cause
logging information to be appended to arbitrary files and execute commands
via the SET TRC_FILE or SET LOG_FILE commands";

  tag_impact =
"Successful exploitation will allow attackers to gain access to an operating
system account and execute commands.

Impact Level: Application/System";

  tag_affected =
"Oracle Database Server versions 7.3.4, 8.0.6, and 8.1.6 are affected";

  tag_solution =
"Apply patches from below link,
http://metalink.oracle.com

*****
NOTE: Ignore this warning if above mentioned patch is installed.
*****";


  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "summary" , value : tag_summary);

  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/1853");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/5380");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  script_mandatory_keys("OracleDatabaseServer/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");
include("global_settings.inc");

## Variable initialisation
port = "";
ver = "";

## Get Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Get Version
if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(ver =~ "^(8\.[0|1]\.|7\.3\.)")
{
  if(version_is_equal(version:ver, test_version:"7.3.4") ||
     version_is_equal(version:ver, test_version:"8.0.6") ||
     version_is_equal(version:ver, test_version:"8.1.6"))
  {
    security_message(port);
  }
}
