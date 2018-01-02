###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_ftpd_auth_bypass_vuln.nasl 8228 2017-12-22 07:29:52Z teissa $
#
# Open-FTPD Authentication Bypass Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to bypass certain
security restrictions and execute FTP commands without any authentication.

Impact Level: Application";

tag_affected = "Open&Compact FTP Server (Open-FTPD) Version 1.2 and prior.";

tag_insight = "The flaw is due to access not being restricted to various FTP
commands before a user is properly authenticated. This can be exploited to
execute FTP commands without any authentication.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Open&Compact FTP Server (Open-FTPD) and is
prone to authentication bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801228");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-07-16 18:57:03 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-2620");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Open-FTPD Authentication Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/13932");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40284");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("ftp_func.inc");

## Get FTP port
port = get_kb_item("Services/ftp");
if(!port) {
  port = 21;
}

## Check port status
if(!get_port_state(port)) {
  exit(0);
}

## Confirm Open-FTPD
banner = get_ftp_banner(port:port);
if("Gabriel's FTP Server" >!< banner) {
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Try to execute LIST command without authentication
ftp_send_cmd(socket:soc, cmd:"LIST");
result = ftp_recv_listing(socket:soc);
close(soc);

## Check the FTP status message
if("226 Transfert Complete" >< result)
{
  security_message(port:port);
  exit(0);
}
