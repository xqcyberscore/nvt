###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_loadrunner_vts_comp_xss_vuln.nasl 9081 2018-03-12 07:31:35Z cfischer $
#
# HPE LoadRunner Virtual Table Server (VTS) Component Cross-Site Scripting Vulnerability
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

CPE = "cpe:/a:hp:loadrunner";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812938");
  script_version("$Revision: 9081 $");
  script_cve_id("CVE-2017-8953");
  script_bugtraq_id(100338);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-03-12 08:31:35 +0100 (Mon, 12 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-02-19 15:32:13 +0530 (Mon, 19 Feb 2018)");
  script_name("HPE LoadRunner Virtual Table Server (VTS) Component Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with HPE LoadRunner
  and is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to potential errors in
  the Virtual Table Server (VTS) component of application.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to execute arbitrary script code in the browser of an unsuspecting
  user in the context of the affected site.

  Impact Level: Application.");

  script_tag(name:"affected", value:"HPE LoadRunner version 12.53 and earlier.");

  script_tag(name:"solution", value:"Upgrade to HPE LoadRunner to version 12.55
  or later. For details refer to,
  https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbgn03764en_us");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbgn03764en_us");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_hpe_loadrunner_detect.nasl");
  script_mandatory_keys("HPE/LoadRunner/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

##  HPE LoadRunner 12.55 == 12.55.646.0
if(version_is_less(version:vers, test_version:"12.55.646.0"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.55", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
