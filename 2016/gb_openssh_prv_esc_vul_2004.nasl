###############################################################################
#OpenVAS Vulnerability Test
# $Id: gb_openssh_prv_esc_vul_2004.nasl 9585 2018-04-24 11:46:06Z asteins $
#
# OpenBSD OpenSSH 3.9 Port Bounce Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107069");
  script_version("$Revision: 9585 $");
  script_cve_id("CVE-2004-1653");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-24 13:46:06 +0200 (Tue, 24 Apr 2018) $");
  script_tag(name:"creation_date", value:"2016-10-25 11:19:11 +0530 (Tue, 25 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenBSD OpenSSH 3.9 Port Bounce Vulnerability");

  script_tag(name:"summary", value:"This host is running OpenSSH and is prone
  to privilege escalation.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to default configuration for OpenSSH which enables AllowTcpForwarding.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to perform a port bounce,
  when configured with an anonymous access program such as AnonCVS.");

  script_tag(name:"affected", value:"OpenSSH 3.9 and previous versions");

  script_tag(name:"solution", value:"Upgrade to the latest version of OpenSSH.
  For updates refer to https://www.openssh.com/openbsd.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"https://www.openssh.com/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!sshPort = get_app_port(cpe:CPE)){
  exit(0);
}
if(!sshVer = get_app_version(cpe:CPE, port:sshPort)){
  exit(0);
}

if(version_is_less_equal(version:sshVer, test_version:"3.9"))
{
  report = report_fixed_ver(installed_version:sshVer, fixed_version:"See references");
  security_message(data:report, port:sshPort);
  exit(0);
}

exit(99);
