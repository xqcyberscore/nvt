###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_46155.nasl 7019 2017-08-29 11:51:27Z teissa $
#
# OpenSSH Legacy Certificate Signing Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

tag_summary = "Checks whether OpenSSH is prone to an information-disclosure vulnerability.

Successful exploits will allow attackers to gain access to sensitive
information; this may lead to further attacks.

Versions 5.6 and 5.7 of OpenSSH are vulnerable.";

tag_vuldetect = "The SSH banner is analysed for presence of openssh and the version
information is then taken from that banner.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103064);
 script_version("$Revision: 7019 $");
 script_tag(name:"last_modification", value:"$Date: 2017-08-29 13:51:27 +0200 (Tue, 29 Aug 2017) $");
 script_tag(name:"creation_date", value:"2011-02-07 12:50:03 +0100 (Mon, 07 Feb 2011)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2011-0539");
 script_bugtraq_id(46155);

 script_name("OpenSSH Legacy Certificate Signing Information Disclosure Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46155");
 script_xref(name : "URL" , value : "http://www.openssh.com/txt/release-5.8");
 script_xref(name : "URL" , value : "http://www.openssh.com");

 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "summary" , value : tag_summary);
 script_mandatory_keys("openssh/detected");
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/ssh");
if(!port) port = 22;

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);

version = eregmatch(pattern:"ssh-.*openssh[_-]{1}([0-9.]+[p0-9]*)", string: tolower(banner));
if(isnull(version[1]))exit(0);

if(version_in_range(version: version[1], test_version: "5.6", test_version2: "5.7")) {
 security_message(port);
 exit(0);
}

exit(0);
