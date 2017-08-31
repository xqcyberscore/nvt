###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_65674.nasl 6724 2017-07-14 09:57:17Z teissa $
#
# OpenSSH 'ssh-keysign.c' Local Information Disclosure Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.105002";

tag_insight = "ssh-keysign.c in ssh-keysign in OpenSSH before 5.8p2 on
certain platforms executes ssh-rand-helper with unintended open file
descriptors, which allows local users to obtain sensitive key information
via the ptrace system call.";

tag_impact = "Local attackers can exploit this issue to obtain sensitive
information. Information obtained may lead to further attacks.";

tag_affected = "Versions prior to OpenSSH 5.8p2 are vulnerable.";
tag_summary = "OpenSSH is prone to a local information-disclosure vulnerability.";

tag_solution = "Updates are available.";
tag_vuldetect = "Check the version.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(65674);
 script_cve_id("CVE-2011-4327");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_version ("$Revision: 6724 $");

 script_name("OpenSSH 'ssh-keysign.c' Local Information Disclosure Vulnerability");

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65674");
 script_xref(name:"URL", value:"http://www.openssh.com");
 script_xref(name:"URL", value:"http://www.openssh.com/txt/portable-keysign-rand-helper.adv");
 
 script_tag(name:"last_modification", value:"$Date: 2017-07-14 11:57:17 +0200 (Fri, 14 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-04-09 12:29:38 +0200 (Wed, 09 Apr 2014)");
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

if(version_is_less(version:ver[1], test_version:"5.8p2")) {

  security_message(port:port);
  exit(0);
}  

exit(0);

