###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipswitch_imail_remote_code_exec_vuln.nasl 7484 2017-10-18 13:29:18Z cfischer $
#
# Ipswitch IMail Server SMTPD RCE Vulnerability (ETRE/ETCETERABLUE)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ipswitch:imail_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811255");
  script_version("$Revision: 7484 $");
  script_cve_id("CVE-2017-12638", "CVE-2017-12639");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-18 15:29:18 +0200 (Wed, 18 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-07-26 12:49:28 +0530 (Wed, 26 Jul 2017)");
  script_name("Ipswitch IMail Server SMTPD RCE Vulnerability (ETRE/ETCETERABLUE)");

  script_tag(name:"summary", value:"This host is running Ipswitch Collaboration
  Suite/IMail Server and is prone to remote code execution.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of a SMTP banner response and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to some unspecified buffer
  overflow error in the application as disclosed by Shadow Brokers.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow
  remote attackers to execute arbitrary code on the target system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"IMail Server all versions prior to 12.5.6");

  script_tag(name:"solution", value:"Upgrade to IMail Server version 12.5.6 or
  later. For details refer to
  http://docs.ipswitch.com/_Messaging/IMailServer/v12.5.6/ReleaseNotes/index.htm");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name : "URL" , value : "https://github.com/misterch0c/shadowbroker");
  script_xref(name : "URL" , value : "http://docs.ipswitch.com/_Messaging/IMailServer/v12.5.6/ReleaseNotes/index.htm");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_ipswitch_imail_server_detect.nasl");
  script_mandatory_keys("Ipswitch/IMail/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!imVer = get_app_version(cpe:CPE, nofork:TRUE)) exit(0);

if(version_is_less(version:imVer, test_version:"12.5.6"))
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:"12.5.6");
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
