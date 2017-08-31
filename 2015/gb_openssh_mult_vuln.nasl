###############################################################################
#OpenVAS Vulnerability Test
# $Id: gb_openssh_mult_vuln.nasl 6497 2017-06-30 09:58:54Z teissa $
#
# OpenSSH Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806052");
  script_version("$Revision: 6497 $");
  script_cve_id("CVE-2015-6564", "CVE-2015-6563", "CVE-2015-5600");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-06-30 11:58:54 +0200 (Fri, 30 Jun 2017) $");
  script_tag(name:"creation_date", value:"2015-09-15 10:17:32 +0530 (Tue, 15 Sep 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSH Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running OpenSSH and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:
  - Use-after-free vulnerability in the 'mm_answer_pam_free_ctx' function in
  monitor.c in sshd.
  - Vulnerability in 'kbdint_next_device' function in auth2-chall.c in sshd.
  - vulnerability in the handler for the MONITOR_REQ_PAM_FREE_CTX request.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain privileges, to conduct impersonation attacks, to conduct brute-force
  attacks or cause a denial of service.

  Impact Level: Application");

  script_tag(name:"affected", value:"OpenSSH versions before 7.0");

  script_tag(name:"solution", value:"Upgrade to OpenSSH 7.0 or later.
  For updates refer to http://www.openssh.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2015/Aug/54");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2015/07/23/4");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("openssh/detected");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
sshPort = 0;
sshdVer = "";

## Get HTTP Port
if(!sshPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get Version
if(!sshVer = get_app_version(cpe:CPE, port:sshPort)){
  exit(0);
}

## Checking for Vulnerable version
if(version_is_less(version:sshVer, test_version:"7.0"))
{
  report = 'Installed version: ' + sshVer + '\n' +
           'Fixed version:     7.0' + '\n';

  security_message(data:report, port:sshPort);
  exit(0);
}
