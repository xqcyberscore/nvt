###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_user_enumeration_vuln_aug18_win.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# OpenSSH User Enumeration Vulnerability-Aug18 (Windows)
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

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813863");
  script_version("$Revision: 12116 $");
  script_cve_id("CVE-2018-15473");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-20 17:27:42 +0530 (Mon, 20 Aug 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OpenSSH User Enumeration Vulnerability-Aug18 (Windows)");

  script_tag(name:"summary", value:"This host is installed with openssh and
  is prone to user enumeration vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to not delaying bailout for
  an invalid authenticating user until after the packet containing the request
  has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and
  auth2-pubkey.c");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  attacker to test whether a certain user exists or not (username enumeration)
  on a target OpenSSH server.");

  script_tag(name:"affected", value:"OpenSSH version 7.7 and prior on Windows.");

  script_tag(name:"solution", value:"No known solution is available as of 21st
  August, 2018. Information regarding this issue will be updated once solution
  details are available. For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name:"URL", value:"http://www.openssh.com");
  script_xref(name:"URL", value:"https://0day.city/cve-2018-15473.html");
  script_xref(name:"URL", value:"https://github.com/openbsd/src/commit/779974d35b4859c07bc3cb8a12c74b43b0a7d1e0");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("ssh_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("openssh/detected", "Host/runs_windows");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!sshPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE, port:sshPort);
sshVer = infos['version'];
sshPath = infos['location'];

if(version_is_less_equal(version:sshVer, test_version:"7.7"))
{
  report = report_fixed_ver(installed_version:sshVer, fixed_version:'NoneAvailable', install_path:sshPath);
  security_message(port:sshPort, data:report);
  exit(0);
}
