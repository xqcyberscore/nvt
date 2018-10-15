###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_dos_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# OpenSSH Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.806048");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-6565");
  script_bugtraq_id(75990);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-09-10 14:36:41 +0530 (Thu, 10 Sep 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSH Denial of Service Vulnerability");

  script_tag(name:"summary", value:"This host is running OpenSSH and is prone
  to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to sshd uses world-writable
  permissions for TTY devices.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users
  to cause a denial of service (terminal disruption) or possibly have unspecified
  other impact.");

  script_tag(name:"affected", value:"OpenSSH versions 6.8 and 6.9");

  script_tag(name:"solution", value:"Upgrade to OpenSSH version 7.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.openssh.com/txt/release-7.0");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/08/22/1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("openssh/detected");
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

if(version_is_equal(version:sshVer, test_version:"6.8") ||
   version_is_equal(version:sshVer, test_version:"6.9"))
{
  report = 'Installed version: ' + sshVer + '\n' +
           'Fixed version:     7.0' + '\n';

  security_message(data:report, port:sshPort);
  exit(0);
}
