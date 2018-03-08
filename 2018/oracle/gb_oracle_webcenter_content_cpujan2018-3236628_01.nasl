###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_webcenter_content_cpujan2018-3236628_01.nasl 9039 2018-03-07 10:56:54Z santu $
#
# Oracle WebCenter Content Unspecified Vulnerability-01 (cpujan2018-3236628)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:oracle:webcenter_content";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812959");
  script_version("$Revision: 9039 $");
  script_cve_id("CVE-2018-2564");
  script_bugtraq_id(102541);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-03-07 11:56:54 +0100 (Wed, 07 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-06 11:17:44 +0530 (Tue, 06 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); ##Patch is available as solution
  script_name("Oracle WebCenter Content Unspecified Vulnerability-01 (cpujan2018-3236628)");

  script_tag(name: "summary" , value:"The host is running Oracle WebCenter Content
  and is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaws exist due to error in the 'Content
  Server' component.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  can result in unauthorized creation, deletion or modification access to critical
  data or all Oracle WebCenter Content accessible data as well as unauthorized read
  access to a subset of Oracle WebCenter Content accessible data.

  Impact Level: Application");

  script_tag(name:"affected", value:"Oracle WebCenter Content version 11.1.1.9.0");

  script_tag(name:"solution", value:"Apply update from the link mentioned below,
  http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_webcenter_content_detect.nasl");
  script_mandatory_keys("Oracle/WebCenter/Content/Version");
  script_require_ports("Services/www", 80, 443);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

webPort = "";
infos = "";
webVer = "";
path = "";

if(!webPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:webPort, exit_no_version:TRUE);
webVer = infos['version'];
path = infos['location'];

if(webVer == "11.1.1.9.0")
{
  report = report_fixed_ver(installed_version:webVer, fixed_version: "Apply the patch", install_path:path);
  security_message(port:webPort, data:report);
  exit(0);
}
exit(0);
