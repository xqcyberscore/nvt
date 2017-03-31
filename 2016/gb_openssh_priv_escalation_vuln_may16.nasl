###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_priv_escalation_vuln_may16.nasl 5527 2017-03-09 10:00:25Z teissa $
#
# OpenSSH Privilege Escalation Vulnerability - May16
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807574");
  script_version("$Revision: 5527 $");
  script_cve_id("CVE-2015-8325");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-09 11:00:25 +0100 (Thu, 09 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-05-02 15:45:55 +0530 (Mon, 02 May 2016)");
  script_name("OpenSSH Privilege Escalation Vulnerability - May16");

  script_tag(name:"summary", value:"This host is installed with openssh and
  is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  'do_setup_env function' in 'session.c' script in sshd which trigger a crafted 
  environment for the /bin/login program when the UseLogin feature is enabled 
  and PAM is configured to read .pam_environment files in user home directories.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow
  local users to gain privileges.

  Impact Level: Application");

  script_tag(name:"affected", value:"OpenSSH versions through 7.2p2");

  script_tag(name:"solution", value:"Upgrade to OpenSSH version 7.2p2-3 or later.
  For updates refer to http://www.openssh.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name : "URL" , value : "https://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-8325.html");
  script_xref(name : "URL" , value : "https://anongit.mindrot.org/openssh.git/commit/?id=85bdcd7c92fe7ff133bbc4e10a65c91810f88755");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("openssh/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

# Variable Initialization
sshPort = "";
sshVer = "";

## get the port
if(!sshPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!sshVer = get_app_version(cpe:CPE, port:sshPort)){
  exit(0);
}

## Grep for vulnerable version
if(sshVer =~ "^[0-6]\." || sshVer =~ "^7\.[0-1]($|[^0-9])" || sshVer =~ "7.2($|p1|p2)")
{
  report = report_fixed_ver(installed_version:sshVer, fixed_version:"7.2p2-3");
  security_message(port:sshPort, data:report);
  exit(0);
}
