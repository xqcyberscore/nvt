###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_58162.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# OpenSSH  Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103939");
 script_bugtraq_id(58162);
 script_cve_id("CVE-2010-5107");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_version ("$Revision: 6715 $");

 script_name("OpenSSH  Denial of Service Vulnerability");

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58162");
 script_xref(name:"URL", value:"http://www.openssh.com");
 
 script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-04-09 12:16:30 +0200 (Wed, 09 Apr 2014)");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);

 script_tag(name : "impact" , value :
"Exploiting this issue allows remote attackers to trigger denial-of-
service conditions.");
 script_tag(name : "vuldetect" , value :
"Compare the version retrieved from the banner with the affected range.");
 script_tag(name : "insight" , value :
"The default configuration of OpenSSH through 6.1 enforces a fixed
time limit between establishing a TCP connection and completing a login, which
makes it easier for remote attackers to cause a denial of service
(connection-slot exhaustion) by periodically making many new TCP connections.");
 script_tag(name : "solution" , value : "Updates are available.");
 script_tag(name : "summary" , value :
"OpenSSH is prone to a remote denial-of-service vulnerability.");
 script_tag(name : "affected" , value : "OpenSSH 6.1 and prior");

 script_mandatory_keys("openssh/detected");

 exit(0);
}

include("version_func.inc");
include("global_settings.inc");

port = get_kb_item("Services/ssh");
if(!port){
    port = 22;
}

if(!get_port_state(port))exit(0);

banner = get_kb_item("SSH/banner/" + port );
if(!banner || "openssh" >!< tolower(banner)) {
    exit(0); 
}

ver = eregmatch(pattern:"ssh-.*openssh[_-]{1}([0-9.]+[p0-9]*)", string:tolower(banner));

if(isnull(ver[1])){
   exit(0);
}

if(version_is_less_equal(version:ver[1], test_version:"6.1")) {

  security_message(port:port);
  exit(0);
}  

exit(0);

