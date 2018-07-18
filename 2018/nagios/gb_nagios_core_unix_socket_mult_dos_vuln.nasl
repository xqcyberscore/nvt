###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_core_unix_socket_mult_dos_vuln.nasl 10537 2018-07-18 07:58:47Z cfischer $
#
# Nagios Core 'unix socket' Multiple Denial of Service Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:nagios:nagios";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813262");
  script_version("$Revision: 10537 $");
  script_cve_id("CVE-2018-13457", "CVE-2018-13458", "CVE-2018-13441");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-07-18 09:58:47 +0200 (Wed, 18 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-13 14:55:37 +0530 (Fri, 13 Jul 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Nagios Core 'unix socket' Multiple Denial of Service Vulnerabilities");

  script_tag(name:"summary", value:"The host is running Nagios Core and is prone
  to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exists due to error in 'qh_echo',
 'qh_core' and 'qh_help'. which allows attackers to cause a local
  denial-of-service condition.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a denial of service.

  Impact Level: Application");

  script_tag(name:"affected", value:"Nagios Core version 4.4.1 and earlier.");

  script_tag(name:"solution", value:"No known solution is available as of
  09th July, 2018. Information regarding this issue will be updated once
  solution details are available. For updates refer to Reference link.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_xref(name:"URL", value:"https://gist.github.com/fakhrizulkifli/87cf1c1ad403b4d40a86d90c9c9bf7ab");
  script_xref(name:"URL", value:"https://gist.github.com/fakhrizulkifli/40f3daf52950cca6de28ebec2498ff6e");
  script_xref(name:"URL", value:"https://gist.github.com/fakhrizulkifli/8df4a174158df69ebd765f824bd736b8");
  script_xref(name:"URL", value:"https://www.nagios.org/downloads/nagios-core");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("nagios_detect.nasl");
  script_mandatory_keys("nagios/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!nagPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location( cpe:CPE, port:nagPort, exit_no_version:TRUE);
nagVer = infos['version'];
nagPath = infos['location'];

if(version_is_less_equal(version:nagVer, test_version:"4.4.1"))
{
  report = report_fixed_ver(installed_version:nagVer, fixed_version:"NoneAvailable", install_path:nagPath);
  security_message(data:report, port:nagPort);
  exit(0);
}
