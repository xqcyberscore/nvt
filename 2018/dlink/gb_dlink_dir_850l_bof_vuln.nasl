###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir_850l_bof_vuln.nasl 9424 2018-04-10 11:34:04Z cfischer $
#
# D-Link DIR-850L Stack-Based Buffer Overflow Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/o:d-link:dir-850l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813008");
  script_version("$Revision: 9424 $");
  script_cve_id("CVE-2017-3193");
  script_bugtraq_id(96747);
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-10 13:34:04 +0200 (Tue, 10 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-03-08 16:47:29 +0530 (Thu, 08 Mar 2018)");
  script_name("D-Link DIR-850L Stack-Based Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"This host has D-Link DIR-850L device
  and is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient
  validation of user-supplied input in the web administration interface of
  the affected system.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  attackers to conduct arbitrary code execution. Failed exploit attempts will
  likely cause a denial-of-service condition.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"D-Link DIR-850L, firmware versions 1.14B07,
  2.07.B05, and possibly others.");

  script_tag(name:"solution", value:"Upgrade to beta firmware releases (versions
  1.14B07 h2ab BETA1 and 2.07B05 h1ke BETA1, depending on the device's hardware
  revision). For updates refer to http://www.dlink.co.in");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name : "URL" , value : "https://www.kb.cert.org/vuls/id/305448");
  script_xref(name : "URL" , value : "https://tools.cisco.com/security/center/viewAlert.x?alertId=52967");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_detect.nasl");
  script_mandatory_keys("host_is_dlink_dir", "dlink_hw_version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

dport = get_app_port(cpe:CPE);
if(!dport){
  exit(0);
}

if(!version = get_app_version(cpe:CPE, port:dport)) exit(0);

if(version == "1.14B07" || version == "2.07B05"){
  report = report_fixed_ver(installed_version: "DIR-850L fw_version " + version, fixed_version: "1.14B07 h2ab BETA1 and 2.07B05 h1ke BETA1");
  security_message(port: dport, data: report);
  exit(0);
}

exit(99);