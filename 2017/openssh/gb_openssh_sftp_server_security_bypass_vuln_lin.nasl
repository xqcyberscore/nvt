###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_sftp_server_security_bypass_vuln_lin.nasl 7599 2017-10-30 09:14:28Z santu $
#
# OpenSSH 'sftp-server' Security Bypass Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.812051");
  script_version("$Revision: 7599 $");
  script_cve_id("CVE-2017-15906");
  script_bugtraq_id(101552);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-30 10:14:28 +0100 (Mon, 30 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-27 13:08:12 +0530 (Fri, 27 Oct 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSH 'sftp-server' Security Bypass Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with openssh and
  is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists in the 'process_open' function
  in sftp-server.c script which does not properly prevent write operations in
  readonly mode.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows
  local users to bypass certain security restrictions and perform unauthorized
  actions. This may lead to further attacks.

  Impact Level: Application");

  script_tag(name:"affected", value:"OpenSSH versions before 7.6 on Linux");

  script_tag(name:"solution", value:"Upgrade to OpenSSH version 7.6 or later.
  For updates refer to http://www.openssh.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://www.openssh.com/txt/release-7.6");
  script_xref(name : "URL" , value : "https://github.com/openbsd/src/commit/a6981567e8e");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("ssh_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("openssh/detected", "Host/runs_unixoide");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

sshPort = "";
sshVer = "";

if(!sshPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!sshVer = get_app_version(cpe:CPE, port:sshPort)){
  exit(0);
}

if(version_is_less(version:sshVer, test_version:"7.6"))
{
  report = report_fixed_ver(installed_version:sshVer, fixed_version:'7.6');
  security_message(port:sshPort, data:report);
  exit(0);
}
exit(0);
