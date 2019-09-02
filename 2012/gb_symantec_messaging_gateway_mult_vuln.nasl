##############################################################################
# OpenVAS Vulnerability Test
#
# Symantec Messaging Gateway Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802453");
  script_version("2019-09-02T07:13:48+0000");
  script_cve_id("CVE-2012-0307", "CVE-2012-0308", "CVE-2012-3579", "CVE-2012-3580",
                "CVE-2012-3581");
  script_bugtraq_id(55138, 55137, 55143, 55141, 55142);
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-09-02 07:13:48 +0000 (Mon, 02 Sep 2019)");
  script_tag(name:"creation_date", value:"2012-09-04 17:27:04 +0530 (Tue, 04 Sep 2012)");
  script_name("Symantec Messaging Gateway Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027449");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/524060");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/50435");
  script_xref(name:"URL", value:"https://www.hkcert.org/my_url/en/alert/12082901");
  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&suid=20120827_00");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
  restrictions, disclose certain sensitive information and conduct cross-site scripting and request forgery attacks.");

  script_tag(name:"affected", value:"Symantec Messaging Gateway version 9.5.x.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Certain input passed via web or email content is not properly sanitised
  before being returned to the user.

  - The application allows users to perform certain actions via HTTP requests
  without performing proper validity checks to verify the requests.

  - An error within the management interface can be exploited to perform
  otherwise restricted actions(modify the underlying web application).

  - An SSH default passworded account that could potentially be leveraged by
  an unprivileged user to attempt to gain additional privilege access.

  - Disclose of excessive component version information during successful
  reconnaissance.");

  script_tag(name:"solution", value:"Upgrade to Symantec Messaging Gateway version 10.0 or later.");

  script_tag(name:"summary", value:"This host is running Symantec Messaging Gateway and is prone to
  multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("ssh_func.inc");

# If optimize_test = no
if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

port = get_ssh_port(default:22);

if(!soc = open_sock_tcp(port))
  exit(0);

user = "support";
pass = "symantec";

login = ssh_login(socket:soc, login:user, password:pass);
if(login == 0) {

  cmd = "cat /etc/Symantec/SMSSMTP/resources";
  res = ssh_cmd(socket:soc, cmd:cmd);

  if(res && "/Symantec/Brightmail" >< res && "SYMANTEC_BASEDIR" >< res) {
    report = 'It was possible to login as user "' + user + '" with password "' + pass + '" and to execute the "' + cmd + '" command. Result:\n\n' + res;
    security_message(port:port, data:report);
    close(soc);
    exit(0);
  }
}

close(soc);
exit(0);