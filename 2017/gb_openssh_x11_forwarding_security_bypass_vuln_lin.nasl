###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_x11_forwarding_security_bypass_vuln_lin.nasl 11816 2018-10-10 10:42:56Z mmartin $
#
# OpenSSH X11 Forwarding Security Bypass Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810769");
  script_version("$Revision: 11816 $");
  script_cve_id("CVE-2016-1908");
  script_bugtraq_id(84427);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 12:42:56 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-21 16:34:59 +0530 (Fri, 21 Apr 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSH X11 Forwarding Security Bypass Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with openssh and
  is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An access flaw was discovered in OpenSSH,
  It did not correctly handle failures to generate authentication cookies for
  untrusted X11 forwarding. A malicious or compromised remote X application
  could possibly use this flaw to establish a trusted connection to the
  local X server, even if only untrusted X11 forwarding was requested.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows
  local users to bypass certain security restrictions and perform unauthorized
  actions. This may lead to further attacks.");

  script_tag(name:"affected", value:"OpenSSH versions before 7.2 on Linux.");

  script_tag(name:"solution", value:"Upgrade to OpenSSH version 7.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/01/15/13");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1298741#c4");
  script_xref(name:"URL", value:"http://www.openssh.com/txt/release-7.2");
  script_xref(name:"URL", value:"https://anongit.mindrot.org/openssh.git/commit/?id=ed4ce82dbfa8a3a3c8ea6fa0db113c71e234416c");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1298741");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("ssh_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("openssh/detected", "Host/runs_unixoide");
  script_require_ports("Services/ssh", 22);
  script_xref(name:"URL", value:"http://www.openssh.com");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!sshPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!sshVer = get_app_version(cpe:CPE, port:sshPort)){
  exit(0);
}

if(version_is_less(version:sshVer, test_version:"7.2"))
{
  report = report_fixed_ver(installed_version:sshVer, fixed_version:'7.2');
  security_message(port:sshPort, data:report);
  exit(0);
}
