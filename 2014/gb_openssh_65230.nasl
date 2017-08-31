###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_65230.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# OpenSSH 'schnorr.c' Remote Memory Corruption Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.105001";

tag_insight = "The hash_buffer function in schnorr.c in OpenSSH through 6.4,
when Makefile.inc is modified to enable the J-PAKE protocol, does not
initialize certain data structures, which might allow remote attackers
to cause a denial of service (memory corruption) or have unspecified
other impact via vectors that trigger an error condition.";

tag_impact = "An attacker can exploit this issue to execute arbitrary code in
context of the application. Failed exploits may result in denial-of-
service conditions.";

tag_affected = "OpenSSH 6.4 and prior with J-PAKE implemented are vulnerable.";
tag_summary = "OpenSSH is prone to a remote memory-corruption vulnerability.";

tag_solution = "Updates are available.";
tag_vuldetect = "Check the version.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(65230);
 script_cve_id("CVE-2014-1692");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_version ("$Revision: 6715 $");

 script_name("OpenSSH 'schnorr.c' Remote Memory Corruption Vulnerability");

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65230");
 script_xref(name:"URL", value:"http://www.openssh.com");
 
 script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-04-09 12:35:11 +0200 (Wed, 09 Apr 2014)");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 script_mandatory_keys("openssh/detected");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

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

if(version_is_less_equal(version:ver[1], test_version:"6.4")) {

  security_message(port:port);
  exit(0);
}  

exit(0);

