###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lost_door_dos_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Lost Door J-Revolution Denial of Service Vulnerability
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

tag_impact = "Successful exploitation will let remote unauthenticated attackers
to cause a denial of service condition.

Impact Level: Application";

tag_affected = "Lost Door J-Revolution version 6";

tag_insight = "The flaw is due to error in handling the message used by LastDoor
which uses a simple clear text protocol with a delimitter.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Lost Door J-Revolution and is prone to
denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801943");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Lost Door J-Revolution Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://www.1337day.com/exploits/16203");
  script_xref(name : "URL" , value : "http://donofjsr.blogspot.com/2011/03/lostdoor-j-revolution-v6.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(7183);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


## Default Lost Door J-Revolution Port 7183
ldPort = 7183 ;

## exit if ports are not listening
if(!get_port_state(ldPort)){
  exit(0);
}

## Open TCP Socket and immediately close the socket
## without sending any data this will trigger an exception
## at server side causing denial of service
soc = open_sock_tcp(ldPort);
if(!soc){
  exit(0);
}
close(soc);

sleep(5);

## Check still Lost Door J-Revolution is listening
soc = open_sock_tcp(ldPort);
if(!soc){
  security_message(ldPort);
}

close(soc);
