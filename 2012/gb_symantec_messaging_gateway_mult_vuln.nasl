##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_messaging_gateway_mult_vuln.nasl 4690 2016-12-06 14:44:58Z cfi $
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
  script_version("$Revision: 4690 $");
  script_cve_id("CVE-2012-0307", "CVE-2012-0308", "CVE-2012-3579", "CVE-2012-3580",
                "CVE-2012-3581");
  script_bugtraq_id(55138, 55137, 55143, 55141, 55142);
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-12-06 15:44:58 +0100 (Tue, 06 Dec 2016) $");
  script_tag(name:"creation_date", value:"2012-09-04 17:27:04 +0530 (Tue, 04 Sep 2012)");
  script_name("Symantec Messaging Gateway Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ssh", 22);

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027449");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/524060");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/50435");
  script_xref(name:"URL", value:"https://www.hkcert.org/my_url/en/alert/12082901");
  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&suid=20120827_00");

  tag_impact = "Successful exploitation will allow attackers to bypass certain security
  restrictions, disclose certain sensitive information and conduct cross-site
  scripting and request forgery attacks.

  Impact Level: System/Application";

  tag_affected = "Symantec Messaging Gateway version 9.5.x";

  tag_insight = "Multiple flaws are due to,
  - Certain input passed via web or email content is not properly sanitised
    before being returned to the user.
  - The application allows users to perform certain actions via HTTP requests
    without performing proper validity checks to verify the requests.
  - An error within the management interface can be exploited to perform
    otherwise restricted actions(modify the underlying web application).
  - An SSH default passworded account that could potentially be leveraged by
    an unprivileged user to attempt to gain additional privilege access.
  - Disclose of excessive component version information during successful
    reconnaissance.";

  tag_solution = "Upgrade to Symantec Messaging Gateway version 10.0 or later,
  For updates refer to http://www.symantec.com/messaging-gateway";

  tag_summary = "This host is running Symantec Messaging Gateway and is prone to
  multiple vulnerabilities.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


include("ssh_func.inc");

soc = "";
cmd = "";
port = "";
login = "";

## Get the SSH port
port = get_kb_item("Services/ssh");
if(!port){
  port = 22;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Create SSH a socket
if(!soc = open_sock_tcp(port)){
  exit(0);
}

## Try to login with default credentials
login = ssh_login (socket:soc, login:"support", password:"symantec");

## Confirm login success
if(login == 0)
{
 ## Read the configuration file of Symantec Messaging Gateway
 cmd = ssh_cmd(socket:soc, cmd:"cat /etc/Symantec/SMSSMTP/resources");

 ## Confirm read is successful
 if(cmd && "/Symantec/Brightmail" >< cmd && "SYMANTEC_BASEDIR" >< cmd)
 {
   security_message(port:port);
   close(soc);
   exit(0);
 }
}

close(soc);
