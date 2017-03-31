###############################################################################
# OpenVAS Vulnerability Test
# $Id: openssh_32319_remote.nasl 5002 2017-01-13 10:17:13Z teissa $
#
# OpenSSH CBC Mode Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_impact = "Successful exploits will allow attackers to obtain four bytes of plaintext from
  an encrypted session.
  Impact Level: Application";
tag_affected = "Versions prior to OpenSSH 5.2 are vulnerable. Various versions of SSH Tectia
   are also affected.";
tag_insight = "The flaw is due to the improper handling of errors within an SSH session
  encrypted with a block cipher algorithm in the Cipher-Block Chaining 'CBC' mode.";
tag_solution = "Upgrade to higher version
  http://www.openssh.com/portable.html";
tag_summary = "The host is installed with OpenSSH and is prone to information
  disclosure vulnerability.";

if(description)
{
  script_id(100153);
  script_version("$Revision: 5002 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-13 11:17:13 +0100 (Fri, 13 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-04-23 21:21:19 +0200 (Thu, 23 Apr 2009)");
  script_cve_id("CVE-2008-5161");
 script_bugtraq_id(32319);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("OpenSSH CBC Mode Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/32319");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("version_func.inc");
include("global_settings.inc");

port = get_kb_item("Services/ssh");
if(!port) port = 22;

banner = get_kb_item("SSH/banner/" + port);
if ( ! banner ) exit(0);

version = eregmatch(pattern:"ssh-.*openssh[_-]{1}([0-9.]+[p0-9]*)", string: tolower(banner));
if(isnull(version[1]))exit(0);

if(version_is_less(version: version[1], test_version: "5.2")) {
 security_message(port);
 exit(0);
}

exit(0);
