###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sshd_challenge_resp_authentication_bof_vuln.nasl 13568 2019-02-11 10:22:27Z cfischer $
#
# OpenSSH 'sshd' Challenge Response Authentication Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802407");
  script_version("$Revision: 13568 $");
  script_cve_id("CVE-2002-0640");
  script_bugtraq_id(5093);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 11:22:27 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-12-07 18:20:44 +0530 (Wed, 07 Dec 2011)");
  script_name("OpenSSH 'sshd' Challenge Response Authentication Buffer Overflow Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("openssh/detected");

  script_tag(name:"impact", value:"Successful exploitation could allows remote attackers to execute arbitrary
  code and gain escalated privileges.");

  script_tag(name:"affected", value:"OpenSSH versions 2.3.1 to 3.3.");

  script_tag(name:"insight", value:"The flaw is due to an error in handling a large number of responses
  during challenge response authentication when using PAM modules with
  interactive keyboard authentication (PAMAuthenticationViaKbdInt).");

  script_tag(name:"solution", value:"Upgrade to OpenSSH version 3.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The host is running OpenSSH sshd with ChallengeResponseAuthentication
  enabled and is prone to buffer overflow vulnerability.");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/369347");
  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2002-18.html");
  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=102521542826833&w=2");
  script_xref(name:"URL", value:"http://www.openssh.com/");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("ssh_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

banner = get_ssh_server_banner(port:port);
if(!banner)
  exit(0);

ver = eregmatch(pattern:"ssh-.*openssh[_-]{1}([0-9.]+[p0-9]*)", string:tolower(banner));
if(!ver[1])
 exit(0);

if(ver[1] =~ "^[23]\..+")
{
  if(version_is_less(version:ver[1], test_version:"3.4"))
  {
    auth = get_kb_item("SSH/supportedauth/" + port);
    if(auth)
    {
      ## authentication using PAM modules with interactive keyboard
      ## authentication
      if("keyboard-interactive" >< auth){
        security_message(port);
      }
    }
  }
}
