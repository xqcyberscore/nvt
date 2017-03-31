###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_kace_k1000_sma_label_id_xss_vuln.nasl 2823 2016-03-10 07:27:58Z antu123 $
#
# Dell KACE K1000 LABEL_ID Cross Site Scripting Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804238";
CPE = "cpe:/a:dell:x_dellkace";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 2823 $");
  script_cve_id("CVE-2014-0330");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-03-10 08:27:58 +0100 (Thu, 10 Mar 2016) $");
  script_tag(name:"creation_date", value:"2014-02-14 15:46:39 +0530 (Fri, 14 Feb 2014)");
  script_name("Dell KACE K1000 LABEL_ID Cross Site Scripting Vulnerability");

 tag_summary =
"This host is running Dell KACE K1000 Systems Management Appliance and is prone
to cross site scripting vulnerability.";

  tag_vuldetect =
"Get the installed version of Dell KACE K1000 SMA with the help of detect NVT
and check the version is vulnerable or not.";

  tag_insight =
"The flaw is in adminui/user_list.php script which fails to properly sanitizing
user-supplied input to LABEL_ID parameter.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary
script.

Impact Level: Application";

  tag_affected =
"Dell KACE K1000 Systems Management Appliance version 5.5.90545";

  tag_solution =
"Upgrade to latest version of Dell KACE K1000 SMA or Apply the workaround
mentioned below link,
http://www.kace.com/support/resources/kb/solutiondetail?sol=SOL120154
For updates refer to http://www.kace.com/products/systems-management-appliance ";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/813382");
  script_xref(name : "URL" , value : "http://www.kace.com/support/resources/kb/solutiondetail?sol=SOL120154");
  script_summary("Check the vulnerable versions Dell KACE K1000 Systems Management Appliance");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dell_kace_k1000_sma_detect.nasl");
  script_mandatory_keys("X-DellKACE/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
vers = "";
dPort = 0;

## Get HTTP Port
dPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!dPort){
  exit(0);
}

## Get Dell KACE K1000 Systems Management Appliance version
if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:dPort)){
  exit(0);
}

## check the vulnerable versions
if(vers)
{
  if(version_is_equal(version:vers, test_version:"5.5.90545"))
  {
    security_message(dPort);
    exit(0);
  }
}
